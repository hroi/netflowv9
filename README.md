# A Netflow V9 parser for Rust

Netflow v9 is a flexible format describing network traffic flows. Most commercial network gear
supports exporting traffic flow data in this format.
Netflow v9 is a Cisco protocol and is described in [RFC 3954](https://tools.ietf.org/html/rfc3954).
IPFIX, not currently supported by this library, is a descended protocol standard and is described in [RFC 7011](https://tools.ietf.org/html/rfc7011).

Most of this library is machine-generated from the IPFIX field specifications at
[IANA](http://www.iana.org/assignments/ipfix/ipfix.xhtml). Some fixups have been made to support variable
field lengths in Netflow v9 implementations.

API Docs: https://hroi.github.com/netflowv9/

## Notes on implementation

This library tries to perform as little work as needed. You only pay the parsing costs for the fields that you request.
No heap allocations are made.

The record method names follow IPFIX nomenclature in order to be future proof (and enable machine generated code).

## TODO

- Support IPFIX (Wanted: IPFIX packet captures!)
- Work out how to best handle scopes.
- Make flate2 dependency optional
