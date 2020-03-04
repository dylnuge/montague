mod bigendians;
mod class;
mod errors;
mod flags;
mod names;
mod opcode;
mod packet;
mod question;
mod rcode;
mod rdata;
mod rr;
mod rrtype;

// Reference RFC 1035 ( https://tools.ietf.org/html/rfc1035) and a bajillion
// others that have made updates to it. I've put comments where the element
// isn't coming directly from RFC 1035. RFC 6985 summarizes some updates too.
// See: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
pub use class::DnsClass;
pub use errors::DnsFormatError;
pub use flags::DnsFlags;
pub use opcode::DnsOpcode;
pub use packet::DnsPacket;
pub use question::DnsQuestion;
pub use rcode::DnsRCode;
pub use rdata::DnsRecordData;
pub use rr::DnsResourceRecord;
pub use rrtype::DnsRRType;
