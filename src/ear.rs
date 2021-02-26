#![warn(missing_docs, clippy::dbg_macro, clippy::unimplemented)]

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};

use std::fs::File;
use std::io::Write;

use log::{debug, error, trace, warn};

use trust_dns_server::authority::LookupRecords;
use trust_dns_server::proto::rr::Record;
use trust_dns_server::server::{Request, RequestHandler, ResponseHandler};

use std::future::Future;
use std::io;
use std::pin::Pin;

use trust_dns_server::authority::LookupObject;
use trust_dns_server::authority::{
    AuthLookup, MessageRequest, MessageResponse, MessageResponseBuilder,
};
use trust_dns_server::client::op::{Edns, Header, LowerQuery, MessageType, OpCode, ResponseCode};
use trust_dns_server::client::rr::dnssec::{Algorithm, SupportedAlgorithms};
use trust_dns_server::client::rr::rdata::opt::EdnsOption;
use trust_dns_server::client::rr::{RData, RecordType};

use regex::Regex;
use lazy_static::lazy_static;

const SUPPORTED_EDNS_VERSION: u8 = 0;

lazy_static! {
    static ref SUPPORTED_EDNS_ALGORITHMS: SupportedAlgorithms = SupportedAlgorithms::from_vec(&vec!(
        Algorithm::RSASHA256,
        Algorithm::ECDSAP256SHA256,
        Algorithm::ECDSAP384SHA384,
        Algorithm::ED25519,
    ));
}

pub struct Ear {
    writer: Arc<Mutex<File>>,
    filter: Arc<Regex>,
}

impl RequestHandler for Ear {
    type ResponseFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

    /// Determines what needs to happen given the type of request
    ///
    /// # Arguments
    ///
    /// * `request` - the requested action to perform.
    /// * `response_handle` - sink for the response message to be sent
    fn handle_request<R: ResponseHandler>(
        &self,
        request: Request,
        mut response_handle: R,
    ) -> Self::ResponseFuture {
        let request_message = &request.message;
        trace!("request: {:?}", request_message);

        let response_edns: Option<Edns>;

        if let Some(req_edns) = request_message.edns() {
            let mut resp_edns: Edns = Edns::new();
            resp_edns.set_dnssec_ok(true);
            resp_edns.set_max_payload(req_edns.max_payload().max(512));
            resp_edns.set_version(SUPPORTED_EDNS_VERSION);

            // There probably should be a edns version check, maybe not
            let dau = EdnsOption::DAU(*SUPPORTED_EDNS_ALGORITHMS);
            let dhu = EdnsOption::DHU(*SUPPORTED_EDNS_ALGORITHMS);

            resp_edns.set_option(dau);
            resp_edns.set_option(dhu);

            response_edns = Some(resp_edns);
        } else {
            response_edns = None;
        }

        let result = match request_message.message_type() {
            MessageType::Query => match request_message.op_code() {
                OpCode::Query => {
                    debug!("query received: {}", request_message.id());
                    self.respond_with_stub(request_message, response_edns, response_handle);
                    Ok(())
                }
                c => {
                    warn!("unimplemented op_code: {:?}", c);
                    let response = MessageResponseBuilder::new(Some(request_message.raw_queries()));
                    response_handle.send_response(response.error_msg(
                        request_message.id(),
                        request_message.op_code(),
                        ResponseCode::NotImp,
                    ))
                }
            },
            _ => Ok(()),
        };

        if let Err(e) = result {
            error!("request failed: {}", e);
        }

        Box::pin(self.log_usage(&request))
    }
}

impl Ear {
    pub fn new(file: File, filter: Regex) -> Self {
        let writer = Arc::new(Mutex::new(file));
        let filter = Arc::new(filter);

        Ear { writer, filter }
    }

    /// Sends a stub response to every query that matches the defined filtering rule.
    ///
    /// # Arguments
    ///
    /// * `request` - the requested action to perform.
    /// * `response_edns` - information about EDNS settings
    /// * `response_handle` - sink for the response message to be sent
    pub fn respond_with_stub<R: ResponseHandler>(
        &self,
        request: &MessageRequest,
        response_edns: Option<Edns>,
        response_handle: R,
    ) {
        let mut response_header = Header::default();
        response_header.set_id(request.id());
        response_header.set_op_code(OpCode::Query);
        response_header.set_message_type(MessageType::Response);
        response_header.set_response_code(ResponseCode::NoError);
        response_header.set_authoritative(true);

        for query in request.queries().iter() {
            if !self.filter.is_match(&query.name().to_string()) {
                continue;
            }
            let original = query.original();
            let rdata = match original.query_type() {
                RecordType::A => RData::A(Ipv4Addr::LOCALHOST),
                RecordType::AAAA => RData::AAAA(Ipv6Addr::LOCALHOST),
                _ => RData::ZERO,
            };

            let mut record = Record::with(original.name().clone(), original.query_type(), 120);
            record.set_rdata(rdata);

            let rset =
                LookupRecords::new(false, *SUPPORTED_EDNS_ALGORITHMS, Arc::new(record.into()));
            let answers = Box::new(rset) as Box<dyn LookupObject>;

            let empty = Box::new(AuthLookup::default()) as Box<dyn LookupObject>;

            let response: MessageResponse =
                MessageResponseBuilder::new(Some(request.raw_queries())).build(
                    response_header.clone(),
                    answers.iter(),
                    empty.iter(),
                    empty.iter(),
                    empty.iter(),
                );

            let result = send_response(response_edns.clone(), response, response_handle.clone());
            if let Err(e) = result {
                error!("error sending response: {}", e);
            }
        }
    }

    /// Returns a future that would log incoming queries once executed
    ///
    /// # Arguments
    ///
    /// * `request` - the requested action to perform.
    fn log_usage(&self, request: &Request) -> impl Future<Output = ()> + 'static {
        write_to_logfile(
            Arc::clone(&self.writer),
            Arc::clone(&self.filter),
            request.message.queries().to_owned(),
            request.src.to_string(),
        )
    }
}

/// Sends response for quieries back to the client
///
/// # Arguments
/// * `response_edns` - information about EDNS settings
/// * `request` - the requested action to perform.
/// * `response_handle` - sink for the response message to be sent
fn send_response<R: ResponseHandler>(
    response_edns: Option<Edns>,
    mut response: MessageResponse,
    mut response_handle: R,
) -> io::Result<()> {
    if let Some(resp_edns) = response_edns {
        response.set_edns(resp_edns);
    }

    response_handle.send_response(response)
}

/// Writes incoming queries that pass configured filter to a provided logfile
///
/// # Arguments
/// * `write` - file writer
/// * `filter` - the regular expression filter
/// * `queries` - list of incoming queries to log
/// * `src` - the request source ip adddress as a string
async fn write_to_logfile(
    write: Arc<Mutex<File>>,
    filter: Arc<Regex>,
    queries: Vec<LowerQuery>,
    src: String,
) {
    let mut w = write.lock().unwrap();
    for query in queries.iter() {
        if !filter.is_match(&query.name().to_string()) {
            continue;
        }
        writeln!(w, "addr: {} {}", src, query).unwrap();
    }
}
