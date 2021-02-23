
#![warn(missing_docs, clippy::dbg_macro, clippy::unimplemented)]

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc};

use log::{debug, error, trace, warn};


use trust_dns_server::server::{Request, RequestHandler, ResponseHandler};
use trust_dns_server::authority::LookupRecords;
use trust_dns_server::proto::rr::Record;

use std::future::Future;
use std::io;
use std::pin::Pin;

use trust_dns_server::authority::{
    AuthLookup, MessageRequest, MessageResponse, MessageResponseBuilder,
};
use trust_dns_server::authority::{LookupObject};
use trust_dns_server::client::op::{Edns, Header, MessageType, OpCode, ResponseCode};
use trust_dns_server::client::rr::dnssec::{Algorithm, SupportedAlgorithms};
use trust_dns_server::client::rr::rdata::opt::{EdnsOption};
use trust_dns_server::client::rr::{ RData, RecordType};

pub struct Ear {}

impl RequestHandler for Ear {
    type ResponseFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

    /// Determines what needs to happen given the type of request, i.e. Query or Update.
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
        let request_message = request.message;
        trace!("request: {:?}", request_message);

        let response_edns: Option<Edns>;

        // check if it's edns
        if let Some(req_edns) = request_message.edns() {
            let mut response = MessageResponseBuilder::new(Some(request_message.raw_queries()));
            let mut response_header = Header::default();
            response_header.set_id(request_message.id());

            let mut resp_edns: Edns = Edns::new();

            let our_version = 0;
            resp_edns.set_dnssec_ok(true);
            resp_edns.set_max_payload(req_edns.max_payload().max(512));
            resp_edns.set_version(our_version);

            if req_edns.version() > our_version {
                warn!(
                    "request edns version greater than {}: {}",
                    our_version,
                    req_edns.version()
                );
                response_header.set_response_code(ResponseCode::BADVERS);
                response.edns(resp_edns);

                let result =
                    response_handle.send_response(response.build_no_records(response_header));
                if let Err(e) = result {
                    error!("request error: {}", e);
                }
                return Box::pin(async {});
            }

            response_edns = Some(resp_edns);
        } else {
            response_edns = None;
        }

        let result = match request_message.message_type() {
            MessageType::Query => match request_message.op_code() {
                OpCode::Query => {
                    debug!("query received: {}", request_message.id());
                    return Box::pin(self.respond_with_stub(
                        request_message,
                        response_edns,
                        response_handle,
                    ));
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
        Box::pin(async {})
    }
}

impl Ear {
    pub fn new() -> Self {
        Ear {}
    }

    /// TODO
    pub fn respond_with_stub<R: ResponseHandler>(
        &self,
        request: MessageRequest,
        response_edns: Option<Edns>,
        response_handle: R,
    ) -> impl Future<Output = ()> + 'static {
        // let response = MessageResponseBuilder::new(Some(request.raw_queries()));
        let mut response_header = Header::default();
        response_header.set_id(request.id());
        response_header.set_op_code(OpCode::Query);
        response_header.set_message_type(MessageType::Response);
        response_header.set_response_code(ResponseCode::NoError);
        response_header.set_authoritative(true);

        for query in request.queries().iter() {

            let original = query.original();
            let rdata = match original.query_type() {
                RecordType::A => RData::A(Ipv4Addr::LOCALHOST),
                RecordType::AAAA => RData::AAAA(Ipv6Addr::LOCALHOST),
                _ => RData::ZERO,
            };

            let mut record = Record::with(original.name().clone(), original.query_type(), 120);
            record.set_rdata(rdata);


            //TODO use actual dnssec
            let rset = LookupRecords::new(false, SupportedAlgorithms::new(), Arc::new(record.into()));
            let answers = Box::new(rset) as Box<dyn LookupObject>;

            let empty = Box::new(AuthLookup::default()) as Box<dyn LookupObject>;

            let response: MessageResponse = MessageResponseBuilder::new(Some(request.raw_queries()))
                .build(
                    response_header.clone(),
                    answers.iter(), //TODO actual answers
                    empty.iter(),
                    empty.iter(),
                    empty.iter(),
                );

            let result = send_response(response_edns.clone(), response, response_handle.clone());
            if let Err(e) = result {
                error!("error sending response: {}", e);
            }
        }

        Box::pin(async {})
    }
}

fn send_response<R: ResponseHandler>(
    response_edns: Option<Edns>,
    mut response: MessageResponse,
    mut response_handle: R,
) -> io::Result<()> {
    if let Some(mut resp_edns) = response_edns {
        // set edns DAU and DHU
        // send along the algorithms which are supported by this authority
        let mut algorithms = SupportedAlgorithms::new();
        algorithms.set(Algorithm::RSASHA256);
        algorithms.set(Algorithm::ECDSAP256SHA256);
        algorithms.set(Algorithm::ECDSAP384SHA384);
        algorithms.set(Algorithm::ED25519);

        let dau = EdnsOption::DAU(algorithms);
        let dhu = EdnsOption::DHU(algorithms);

        resp_edns.set_option(dau);
        resp_edns.set_option(dhu);

        response.set_edns(resp_edns);
    }

    response_handle.send_response(response)
}
