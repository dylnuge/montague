# Montague

[![Build Status](https://travis-ci.com/Dylnuge/montague.svg?branch=master)](https://travis-ci.com/Dylnuge/montague)

What's in a nameserver, Romeo?

This is a toy DNS server built in Rust. I did this to learn Rust and to
understand DNS better. It's not intended for use in production environments.

🏊 Swim at your own risk!

## Authors

* Dylan Nugent &lt;@dylnuge&gt;

## Functionality

Current functionality is mostly limited to protocol functionality. The dns crate
is capable of parsing and serializing DNS requests so long as they can fit in a
single transmission packet (do not require truncation) and don't contain EDNS
OPT records (because of no handling for the overloaded `class` header uint).

### Future Features

- [ ] Expand DNS protocol library functionality
  - [ ] Support OPT (EDNS) records ([RFC6891](https://tools.ietf.org/html/rfc6891))
  - [ ] Compress names using label pointers in responses
- [ ] Database (authoritative resolver) functionality
  - [ ] Support reading authoritative records from DNS zone files
- [ ] Recursive resolver functionality
- [ ] Robust server functionality
- [ ] Support DNSSEC extensions
- [ ] Support DNS over HTTPS and/or DNS over TLS

## References

There are a bunch of RFCs covering DNS. These are the ones I've been referencing
the most (as well as their errata):
* [RFC1035](https://tools.ietf.org/html/rfc1035)—The original implementation
  spec for DNS
* [RFC1034](https://tools.ietf.org/html/rfc1034)—Defines core concepts of DNS
* [RFC2535](https://tools.ietf.org/html/rfc2535)—DNSSEC extensions
* [RFC3492](https://tools.ietf.org/html/rfc3492)—Punycode, the way DNS labels
  containing Unicode are encoded.
* [RFC6891](https://tools.ietf.org/html/rfc6891)—EDNS0, which adds OPT records

I've also heavily referenced:
* [IANA DNS Parameters](https://www.iana.org/assignments/dns-parameters/dns-parameters.xml)—Used
  heavily in making all the enums; this has most of the DNS header field
  meanings as well as links to which specific RFC encodes them.
