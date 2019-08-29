mod bigendians;
mod class;
mod errors;
mod flags;
mod names;
mod opcode;
mod packet;
mod question;
mod rcode;
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
pub use rr::DnsResourceRecord;
pub use rrtype::DnsRRType;

// *** PUBLIC FUNCTIONS ***
pub fn nx_answer_from_query(packet: &DnsPacket) -> DnsPacket {
    let id = packet.id;
    let flags = DnsFlags {
        qr_bit: true,
        opcode: packet.flags.opcode.to_owned(),
        aa_bit: false,
        tc_bit: false,
        rd_bit: packet.flags.rd_bit,
        ra_bit: false,
        ad_bit: false,
        cd_bit: false,
        rcode: DnsRCode::NXDomain,
    };

    let questions = packet.questions.to_owned();
    let answers = Vec::<DnsResourceRecord>::new();
    let nameservers = Vec::<DnsResourceRecord>::new();
    let addl_recs = Vec::<DnsResourceRecord>::new();

    DnsPacket {
        id,
        flags,
        questions,
        answers,
        nameservers,
        addl_recs,
    }
}
