# DNS-Ear

DNS-Ear listens to incoming DNS queries. Useful for DNS exfiltration in
environments, where possibilities to send out requests are limited.

**Important**: DNS-Ear requires root privileges to listen to default DNS port 53.

## Usage

```shell
USAGE:
    dns-ear [FLAGS] [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information
    -v, --verbose    Enable verbose output. -v for INFO, -vv for DEBUG output

OPTIONS:
    -a, --addr <addr>...       Listening address for DNS queries. Accepts both ipv4 and ipv6 formats. Could be specified
                               multiple times. [default: 0.0.0.0]
    -f, --filter <filter>      Filter queries by regex.
    -l, --logfile <logfile>    Log file to write query log to. [default: queries.log]
    -p, --port <port>          Listening port for DNS queries [default: 53]
```

## Parameters

* `-a`, `--addr` specifies ipv4/ipv6 addresses to listen to. Could be provided multiple times.
  Default: `0.0.0.0`.
* `-f`, `--filter` spicifies [regex] for filtering incoming queries.
 **DNS-Ear does not reply to queries that do not match the specified filter.**
  Example: `.*.dns.yourdomain.com`. Use `'.*'` to disable all filtering.
* `-l`, `--logfile` specify the log filespecifies to write incoming queries to.
  Default: `queries.log`
* `-p`, `--port` specifies the listening port. Default: `53`
* `-v`, `--verbose` enables the verbose output. Use `-v` for INFO and `-vv` for
  DEBUG outputs.

**Important**: using `'.*'` filter for public networks is not recommended due to high
amount of noise.

## Installing

Download a binary for the operation system of your choice from the project releases page.

## (Alternative) Building

DNS-Ear requires a rust distribution to be present in your system for building the project.

```shell
$ RUSTFLAGS='-C link-arg=-s' cargo build --release -p dns-ear
```

## Running

```shell
$ sudo ./target/release/dns-ear -p 53 -a 0.0.0.0 -l queries.log -f .*.dns.example.com
```

## Limitations

Although DNS-Ear is capable of logging any type of query supported by the original
[trust-dns] implementation, it only sends a proper response to A and AAAA queries.

## Contributing

Contributions are welcome!

## Disclaimer

This project is inspired by [dnsbin]. The motivation was to create an alternative
that is distributed in binaries which simplifies use.

The code uses [trust-dns] libraries and is heavily inspired by its [named binary].

## License

Licensed under [MIT license].


[dnsbin]: https://github.com/ettic-team/dnsbin
[regex]: https://en.wikipedia.org/wiki/Regular_expression
[trust-dns]: https://github.com/bluejekyll/trust-dns
[named binary]: https://github.com/bluejekyll/trust-dns/blob/main/bin/src/named.rs
[MIT license]: LICENSE
