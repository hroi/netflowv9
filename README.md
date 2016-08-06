# A Netflow V9 parser for Rust

Netflow v9 is a flexible format describing network traffic flows. Most commercial network gear
supports exporting traffic flow data in this format.
Netflow v9 is a Cisco protocol but described in [RFC 3954](https://tools.ietf.org/html/rfc3954).
IPFIX is a descended protocol standard and is described in [RFC 7011](https://tools.ietf.org/html/rfc7011).

Most of this library is machine-generated from the IPFIX field specifications at [IANA](http://www.iana.org/assignments/ipfix/ipfix.xhtml). Some fixups have been made to support different field lengths in Netflow v9 implementations.

API Docs: https://hroi.github.com/netflowv9/

## TODO

- Support IPFIX - if anyone has real captures of IPFIX packets, please provide them to me.
- Work out how to best handle scopes.

