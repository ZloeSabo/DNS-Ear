// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! The `named` binary for running a DNS server
//!
//! ```text
//! Usage: named [options]
//!       named (-h | --help | --version)
//!
//! Options:
//!    -q, --quiet             Disable INFO messages, WARN and ERROR will remain
//!    -d, --debug             Turn on DEBUG messages (default is only INFO)
//!    -h, --help              Show this message
//!    -v, --version           Show the version of trust-dns
//!    -c FILE, --config=FILE  Path to configuration file, default is /etc/named.toml
//!    -z DIR, --zonedir=DIR   Path to the root directory for all zone files, see also config toml
//!    -p PORT, --port=PORT    Override the listening port
//!    --tls-port=PORT         Override the listening port for TLS connections
//! ```

#![warn(missing_docs, clippy::dbg_macro, clippy::unimplemented)]
#![recursion_limit = "128"]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use clap::{Arg, ArgMatches};
use tokio::net::TcpListener;
use tokio::net::UdpSocket;
use tokio::runtime::{self, Runtime};

use clap::*;
use log::{debug, error, info, trace, warn};

// use trust_dns_client::rr::Name;
use trust_dns_server::authority::{AuthorityObject, Catalog, ZoneType};
#[cfg(feature = "dns-over-tls")]
use trust_dns_server::config::dnssec::{self, TlsCertConfig};
use trust_dns_server::config::{Config, ZoneConfig};
use trust_dns_server::logger;
use trust_dns_server::server::{Request, RequestHandler, ResponseHandler, ServerFuture};
use trust_dns_server::store::file::{FileAuthority, FileConfig};

use trust_dns_server::authority::LookupRecords;
use trust_dns_server::proto::rr::Record;

use std::borrow::Borrow;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;

use trust_dns_server::authority::{
    AuthLookup, MessageRequest, MessageResponse, MessageResponseBuilder,
};
use trust_dns_server::authority::{BoxedLookupFuture, EmptyLookup, LookupError, LookupObject};
use trust_dns_server::client::op::{Edns, Header, LowerQuery, MessageType, OpCode, ResponseCode};
use trust_dns_server::client::rr::dnssec::{Algorithm, SupportedAlgorithms};
use trust_dns_server::client::rr::rdata::opt::{EdnsCode, EdnsOption};
use trust_dns_server::client::rr::{LowerName, RData, RecordType};

// argument name constants for the CLI options
const QUIET_ARG: &str = "quiet";
const DEBUG_ARG: &str = "debug";
const PORT_ARG: &str = "port";
const ADDR_ARG: &str = "addr";

/// Args struct for all options
struct Args {
    pub flag_quiet: bool,
    pub flag_debug: bool,
    pub flag_port: Option<u16>,
    pub flag_addr: Option<Vec<IpAddr>>,
}

impl<'a> From<ArgMatches<'a>> for Args {
    fn from(matches: ArgMatches<'a>) -> Args {
        Args {
            flag_quiet: matches.is_present(QUIET_ARG),
            flag_debug: matches.is_present(DEBUG_ARG),
            flag_port: matches
                .value_of(PORT_ARG)
                .map(|s| u16::from_str_radix(s, 10).expect("bad port argument")),
            flag_addr: matches.values_of(ADDR_ARG).map(|vals| {
                vals.map(|y| y.parse().expect(&format!("Bad address argument: {}", y)))
                    .collect::<Vec<_>>()
            }),
        }
    }
}

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

            // check our version against the request
            // TODO: what version are we?
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

                // TODO: should ResponseHandle consume self?
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
            // TODO think about threading query lookups for multiple lookups, this could be a huge improvement
            //  especially for recursive lookups
            MessageType::Query => match request_message.op_code() {
                OpCode::Query => {
                    debug!("query received: {}", request_message.id());
                    return Box::pin(self.respond_with_stub(
                        request_message,
                        response_edns,
                        response_handle,
                    ));
                }
                // OpCode::Update => {
                //     debug!("update received: {}", request_message.id());
                //     // TODO: this should be a future
                //     // self.update(&request_message, response_edns, response_handle)
                // }
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
            // MessageType::Response => {
            //     warn!(
            //         "got a response as a request from id: {}",
            //         request_message.id()
            //     );
            //     let response = MessageResponseBuilder::new(Some(request_message.raw_queries()));
            //     response_handle.send_response(response.error_msg(
            //         request_message.id(),
            //         request_message.op_code(),
            //         ResponseCode::FormErr,
            //     ))
            // }
            _ => Ok(()),
        };

        if let Err(e) = result {
            error!("request failed: {}", e);
        }
        Box::pin(async {})
    }
}

impl Ear {
    fn new() -> Self {
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

    /// TODO
    pub fn lookup<R: ResponseHandler>(
        &self,
        request: MessageRequest,
        response_edns: Option<Edns>,
        response_handle: R,
    ) -> impl Future<Output = ()> + 'static {
        // let queries_and_authorities:Vec<(usize, Box<dyn AuthorityObject>)> = request
        //     .queries()
        //     .iter()
        //     .enumerate()
        //     // .filter_map(|(i, q)| {
        //     //     self.find(q.name())
        //     //         .map(|authority| (i, authority.box_clone()))
        //     // })
        //     .collect::<Vec<_>>();
        let queries_and_authorities: Vec<(usize, Box<dyn AuthorityObject>)> = vec![];

        if queries_and_authorities.is_empty() {
            let response = MessageResponseBuilder::new(Some(request.raw_queries()));
            send_response(
                response_edns
                    .as_ref()
                    .map(|arc| Borrow::<Edns>::borrow(arc).clone()),
                response.error_msg(request.id(), request.op_code(), ResponseCode::NXDomain),
                response_handle.clone(),
            )
            .map_err(|e| error!("failed to send response: {}", e))
            .ok();
        }

        lookup(
            queries_and_authorities,
            request,
            response_edns,
            response_handle,
        )
    }
}

async fn lookup<R: ResponseHandler + Unpin>(
    queries_and_authorities: Vec<(usize, Box<dyn AuthorityObject>)>,
    request: MessageRequest,
    response_edns: Option<Edns>,
    response_handle: R,
) {
    // TODO: the spec is very unclear on what to do with multiple queries
    //  we will search for each, in the future, maybe make this threaded to respond even faster.
    //  the current impl will return on the first query result
    for (query_idx, authority) in queries_and_authorities {
        let query = &request.queries()[query_idx];
        info!(
            "request: {} found authority: {}",
            request.id(),
            authority.origin()
        );

        // let (response_header, sections) =
        //     build_response(&*authority, request.id(), query, request.edns()).await;

        // let response = MessageResponseBuilder::new(Some(request.raw_queries())).build(
        //     response_header,
        //     sections.answers.iter(),
        //     sections.ns.iter(),
        //     sections.soa.iter(),
        //     sections.additionals.iter(),
        // );
        let response = MessageResponseBuilder::new(Some(request.raw_queries())).error_msg(
            request.id(),
            request.op_code(),
            ResponseCode::NXDomain,
        );

        let result = send_response(response_edns.clone(), response, response_handle.clone());
        if let Err(e) = result {
            error!("error sending response: {}", e);
        }
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

fn main() {
    let args = app_from_crate!()
        .arg(
            Arg::with_name(QUIET_ARG)
                .long(QUIET_ARG)
                .short("q")
                .help("Disable INFO messages, WARN and ERROR will remain")
                .conflicts_with(DEBUG_ARG),
        )
        .arg(
            Arg::with_name(DEBUG_ARG)
                .long(DEBUG_ARG)
                .short("d")
                .help("Turn on DEBUG messages (default is only INFO)")
                .conflicts_with(QUIET_ARG),
        )
        .arg(
            Arg::with_name(PORT_ARG)
                .long(PORT_ARG)
                .short("p")
                .help("Listening port for DNS queries, overrides any value in config file")
                .value_name(PORT_ARG),
        )
        .arg(
            Arg::with_name(ADDR_ARG)
                .long(ADDR_ARG)
                .short("a")
                .help("todo")
                .value_name(ADDR_ARG)
                .multiple(true),
        )
        .get_matches();

    let args: Args = args.into();

    // TODO: this should be set after loading config, but it's necessary for initial log lines, no?
    if args.flag_quiet {
        logger::quiet();
    } else if args.flag_debug {
        logger::debug();
    } else {
        logger::default();
    }

    let mut runtime = runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(4)
        .thread_name("trust-dns-server-runtime")
        .build()
        .expect("failed to initialize Tokio Runtime");
    // let mut catalog: Catalog = Catalog::new();

    let tcp_request_timeout: Duration = Duration::from_secs(10);
    let listen_port: u16 = args.flag_port.unwrap();

    let mut listen_addrs: Vec<IpAddr> = args.flag_addr.unwrap_or_default();

    if listen_addrs.is_empty() {
        listen_addrs.push(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
    }

    let sockaddrs: Vec<SocketAddr> = listen_addrs
        .iter()
        .flat_map(|x| (*x, listen_port).to_socket_addrs().unwrap())
        .collect();

    let catalog = Ear::new();
    let mut server = ServerFuture::new(catalog);

    // load all the listeners
    for udp_socket in &sockaddrs {
        info!("binding UDP to {:?}", udp_socket);
        let udp_socket = runtime
            .block_on(UdpSocket::bind(udp_socket))
            .unwrap_or_else(|_| panic!("could not bind to udp: {}", udp_socket));

        info!(
            "listening for UDP on {:?}",
            udp_socket
                .local_addr()
                .expect("could not lookup local address")
        );

        let _guard = runtime.enter();
        server.register_socket(udp_socket);
    }

    // and TCP as necessary
    for tcp_listener in &sockaddrs {
        info!("binding TCP to {:?}", tcp_listener);
        let tcp_listener = runtime
            .block_on(TcpListener::bind(tcp_listener))
            .unwrap_or_else(|_| panic!("could not bind to tcp: {}", tcp_listener));

        info!(
            "listening for TCP on {:?}",
            tcp_listener
                .local_addr()
                .expect("could not lookup local address")
        );

        let _guard = runtime.enter();
        server.register_listener(tcp_listener, tcp_request_timeout);
    }

    info!("Server starting up");
    match runtime.block_on(server.block_until_done()) {
        Ok(()) => {
            info!("Stopping dns-ear");
        }
        Err(e) => {
            let error_msg = format!(
                "dns-ear has encountered an error and is going to stop: {}",
                e
            );

            error!("{}", error_msg);
            panic!(error_msg);
        }
    };
}
