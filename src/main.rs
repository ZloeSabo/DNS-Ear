//! The `dns-ear` binary for running a DNS bin server
//!
//! ```text
//! Usage: dns-ear [options]
//!       dns-ear (-h | --help | --version)
//!
//! Options:
//!    -h, --help              Show this message
//!    -v, --version           Show the version of trust-dns
//!    -p PORT, --port=PORT    Override the listening port (default 53)
//!    -a ADDRESS, --addr      Override the listening address (default 0.0.0.0)
//! ```

#![warn(missing_docs, clippy::dbg_macro, clippy::unimplemented)]
#![recursion_limit = "128"]

mod ear;

use std::fs::File;
use std::fs::OpenOptions;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;

use clap::{Arg, ArgMatches};
use tokio::net::TcpListener;
use tokio::net::UdpSocket;
use tokio::runtime::{self};

use clap::{app_from_crate, crate_authors, crate_description, crate_name, crate_version};
use log::{error, info, warn};

use trust_dns_server::logger;
use trust_dns_server::server::ServerFuture;

use regex::Regex;

use ear::Ear;

// argument name constants for the CLI options
const VERBOSE_ARG: &str = "verbose";
const PORT_ARG: &str = "port";
const ADDR_ARG: &str = "addr";
const LOGFILE_ARG: &str = "logfile";
const FILTER_ARG: &str = "filter";

const DEFAULT_PORT: &str = "53";
const DEFAULT_ADDRESS: &str = "0.0.0.0";
const DEFAULT_LOGFILE: &str = "queries.log";

/// Args struct for all options
#[derive(Debug)]
struct Args {
    pub flag_verbose_num: u64,
    pub flag_port: Option<u16>,
    pub flag_addr: Option<Vec<IpAddr>>,
    pub flag_logfile: String,
    pub flag_filter: String,
}

impl<'a> From<ArgMatches<'a>> for Args {
    fn from(matches: ArgMatches<'a>) -> Args {
        Args {
            flag_verbose_num: matches.occurrences_of(VERBOSE_ARG),
            flag_port: matches
                .value_of(PORT_ARG)
                .map(|s| u16::from_str_radix(s, 10).expect("bad port argument")),
            flag_addr: matches.values_of(ADDR_ARG).map(|vals| {
                vals.map(|y| y.parse().expect(&format!("Bad address argument: {}", y)))
                    .collect::<Vec<_>>()
            }),
            flag_logfile: matches
                .value_of(LOGFILE_ARG)
                .map(ToString::to_string)
                .expect("Logfile required"),
            flag_filter: matches
                .value_of(FILTER_ARG)
                .map(ToString::to_string)
                .expect("Filter required"),
        }
    }
}

fn main() {
    let args = app_from_crate!()
        .arg(
            Arg::with_name(VERBOSE_ARG)
                .env("VERBOSE")
                .long(VERBOSE_ARG)
                .short("v")
                .help("Enable verbose output. -v for INFO, -vv for DEBUG output")
                .takes_value(false)
                .multiple(true),
        )
        .arg(
            Arg::with_name(PORT_ARG)
                .default_value(DEFAULT_PORT)
                .long(PORT_ARG)
                .short("p")
                .help("Listening port for DNS queries")
                .value_name(PORT_ARG),
        )
        .arg(
            Arg::with_name(ADDR_ARG)
                .default_value(DEFAULT_ADDRESS)
                .long(ADDR_ARG)
                .short("a")
                .help("Listening address for DNS queries. Accepts both ipv4 and ipv6 formats. Could be specified multiple times.")
                .value_name(ADDR_ARG)
                .multiple(true),
        )
        .arg(
            Arg::with_name(LOGFILE_ARG)
                .default_value(DEFAULT_LOGFILE)
                .long(LOGFILE_ARG)
                .short("l")
                .help("Log file to write query log to.")
                .value_name(LOGFILE_ARG)
        )
        .arg(
            Arg::with_name(FILTER_ARG)
                .long(FILTER_ARG)
                .short("f")
                .help("Filter queries by regex.")
                .value_name(FILTER_ARG)
        )
        .get_matches();

    let args: Args = args.into();

    match args.flag_verbose_num {
        1 => logger::default(),
        2 => logger::debug(),
        _ => logger::quiet(),
    }

    let runtime = runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(4)
        .thread_name("trust-dns-server-runtime")
        .build()
        .expect("failed to initialize Tokio Runtime");

    let tcp_request_timeout = Duration::from_secs(10);
    let listen_port = args.flag_port.unwrap();

    let listen_addrs = args.flag_addr.unwrap_or_default();

    let sockaddrs: Vec<SocketAddr> = listen_addrs
        .iter()
        .flat_map(|x| (*x, listen_port).to_socket_addrs().unwrap())
        .collect();

    let filter: Regex = Regex::new(&args.flag_filter).unwrap();

    // let flag_logfile = args.flag_logfile;
    let path = Path::new(&args.flag_logfile);
    let logfile = OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open(&path)
        .expect("Logfile is not accessible");

    let ear = Ear::new(logfile, filter);
    let mut server = ServerFuture::new(ear);

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
