// Reference RFC 1035 ( https://tools.ietf.org/html/rfc1035) and a bajillion
// others that have made updates to it. I've put comments where the element
// isn't coming directly from RFC 1035.
// See: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml

// *** STRUCTURES AND ENUMS ***

#[allow(dead_code)]
pub struct DnsPacket {
    // DNS transaction ID is a 16 bit number. It's arbitrary when transmitted
    // and copied into the reply so the client knows which replies correspond
    // to which requests if it's asking the same DNS server multiple questions.
    id: u16,
    // 16 more bits for flags which tell us a lot about the DNS packet.
    flags: DnsFlags,
    // u16 for number of: questions (QDCOUNT), answers (ANCOUNT), nameserver
    // records (NSCOUNT), and additional records (ARCOUNT)
    qd_count: u16,
    an_count: u16,
    ns_count: u16,
    ar_count: u16,
    // And the actual records themselves
    questions: Vec<DnsQuestion>,
    answers: Vec<DnsResourceRecord>,
    ns_records: Vec<DnsResourceRecord>,
    addl_records: Vec<DnsResourceRecord>,
}

#[allow(dead_code)]
pub struct DnsFlags {
    // Query/Response: True if this is a response, false if it is a query
    qr_bit: bool,
    // Opcode: A four bit field indicating the DNS operation being performed
    opcode: DnsOpcode,
    // Authoritative Answer: True if this is a response from the server that
    // is the authority for the domain being queried, false otherwise.
    aa_bit: bool,
    // TrunCation: True if the message was truncated for being too long
    tc_bit: bool,
    // Recursion Desired: True if query wants nameserver to resolve this
    // request recursively, false if not. Copied into the response.
    rd_bit: bool,
    // Recursion Available: True if this is a response from a server that
    // supports recursion, false if response is from a server that does not,
    // undefined/ignored in a query
    ra_bit: bool,
    // The next bit is the Z field, which is reserved and should be zero. We
    // don't need it in the struct

    // TODO(dylan): Better understand/document next two DNSSEC flags
    // Authenticated Data: Part of DNSSEC (RFC 2535, 4035 and others). Indicates
    // that DNSSEC was used to authenticate all responses. Only relevant when
    // communicating with trusted nameservers.
    ad_bit: bool,
    // Checking Disabled: Also DNSSEC (RFC 2535, 4035 and others). Indicates
    // DNSSEC should not be used/was not used in serving this response
    cd_bit: bool,
    // RCode: A four bit field indicating the status of a response.
    // Undefined/ignored in queries.
    rcode: DnsRCode
}

#[allow(dead_code)]
pub struct DnsQuestion {
    // TODO(dylan): implement
}

#[allow(dead_code)]
pub struct DnsResourceRecord {
    // TODO(dylan): implement
}

#[allow(dead_code)]
pub enum DnsOpcode {
    // Opcode 0: standard query
    Query,
    // Opcode 1: inverse query (obsoleted by RFC 3425)
    IQuery,
    // Opcode 2: server status request
    Status,
    // 3 reserved for future use
    // Opcode 4: notify of zone change (RFC 1996)
    Zone,
    // Opcode 5: dynamic update to DNS records (RFC 2136)
    Update,
    // Opcode 6: DNS Stateful Operations (RFC 8490)
    DSO,
    // 7-15 reserved for future use
}

#[allow(dead_code)]
pub enum DnsRCode {
    // 0: No error
    NoError,
    // 1: Format error - NS couldn't interpret query
    FormError,
    // 2: Server failure - NS couldn't process query
    ServFail,
    // 3: Name error - The domain does not exist
    NXDomain,
    // 4: Not Implemented - The requested operation can't be done by this NS
    NotImp,
    // 5: Refused - Namserver refused operation for an unspecified reason
    Refused,
    // TODO(dylan): document what 6-11 actually mean
    YXDomain,
    YXRRSet,
    NXRRSet,
    NotAuth,
    NotZone,
    DSOTypeNI,
    // 12-15 are reserved
    // TODO(dylan): RCodes above 16 are defined but only for use in records,
    // since the RCode field in the header is too short to store numbers that
    // high. Add those here. (RFC 2929 explicitly discusses this, various other
    // RFCs implement them)
}

// *** PUBLIC FUNCTIONS ***

// Converts raw bytes into a DnsPacket struct
// TODO(dylan): real errors instead of strings
pub fn process_packet_bytes(packet_bytes: &[u8]) -> Result<DnsPacket, String> {
    let id: u16;
    let flags: DnsFlags;
    // TODO(dylan) remove default values
    let qd_count: u16;
    let an_count: u16;
    let ns_count: u16;
    let ar_count: u16;
    let mut questions: Vec<DnsQuestion> = Vec::new();
    let mut answers: Vec<DnsResourceRecord> = Vec::new();
    let mut ns_records: Vec<DnsResourceRecord> = Vec::new();
    let mut addl_records: Vec<DnsResourceRecord>= Vec::new();

    // TODO(dylan): Error checking, e.g. DNS request too short
    // Read the first two bytes as a big-endian u16 containing transaction id
    id = parse_big_endian_bytes_to_u16(&packet_bytes[0..2]);
    // Next two bytes are flags
    flags = parse_dns_flags(&packet_bytes[2..4])?;
    // Counts are next four u16s (big-endian)
    qd_count = parse_big_endian_bytes_to_u16(&packet_bytes[4..6]);
    an_count = parse_big_endian_bytes_to_u16(&packet_bytes[6..8]);
    ns_count = parse_big_endian_bytes_to_u16(&packet_bytes[8..10]);
    ar_count = parse_big_endian_bytes_to_u16(&packet_bytes[10..12]);

    Ok(DnsPacket{
        id, flags, qd_count, an_count, ns_count,
        ar_count, questions, answers, ns_records, addl_records,
    })
}

// Debug function which prints data from packets out
pub fn print_packet(packet: &DnsPacket) {
    println!("id: {}", packet.id);
    println!("qr: {}, aa: {}, tc: {}, rd: {}, ra: {}",
             packet.flags.qr_bit,
             packet.flags.aa_bit,
             packet.flags.tc_bit,
             packet.flags.rd_bit,
             packet.flags.ra_bit);
    println!("qdcount: {}, ancount: {}, nscount: {}, arcount: {}",
             packet.qd_count,
             packet.an_count,
             packet.ns_count,
             packet.ar_count);
}

// *** PRIVATE FUNCTIONS ***
// Parse the next two bytes in the passed slice into a u16, assuming they're
// encoded big-endian (network byte order)
// TODO(dylan): there's probably more idiomatic ways of handling byte
// conversions in Rust. As is, this function isn't even checking if the slice
// passed to it is the right size.
fn parse_big_endian_bytes_to_u16(bytes: &[u8]) -> u16 {
    ((bytes[0] as u16) << 8) + (bytes[1] as u16)
}

fn parse_dns_flags(bytes: &[u8]) -> Result<DnsFlags, String> {
    let qr_bit: bool = (bytes[0] >> 7) & 1 == 1;
    let aa_bit: bool = (bytes[0] >> 2) & 1 == 1;
    let tc_bit: bool = (bytes[0] >> 1) & 1 == 1;
    let rd_bit: bool = (bytes[0]) & 1 == 1;
    let ra_bit: bool = (bytes[1] >> 7) & 1 == 1;
    let ad_bit: bool = (bytes[1] >> 5) & 1 == 1;
    let cd_bit: bool = (bytes[1] >> 4) & 1 == 1;

    let opcode_val: u8 = (bytes[0] >> 3) & 0b1111;
    let rcode_val: u8 = (bytes[1]) & 0b1111;

    let opcode = match opcode_val {
        0 => Ok(DnsOpcode::Query),
        1 => Ok(DnsOpcode::IQuery),
        2 => Ok(DnsOpcode::Status),
        4 => Ok(DnsOpcode::Zone),
        5 => Ok(DnsOpcode::Update),
        6 => Ok(DnsOpcode::DSO),
        _ => Err("Invalid opcode")
    }?;

    let rcode = match rcode_val {
        0 => Ok(DnsRCode::NoError),
        1 => Ok(DnsRCode::FormError),
        2 => Ok(DnsRCode::ServFail),
        3 => Ok(DnsRCode::NXDomain),
        4 => Ok(DnsRCode::NotImp),
        5 => Ok(DnsRCode::Refused),
        6 => Ok(DnsRCode::YXDomain),
        7 => Ok(DnsRCode::YXRRSet),
        8 => Ok(DnsRCode::NXRRSet),
        9 => Ok(DnsRCode::NotAuth),
        10 => Ok(DnsRCode::NotZone),
        11 => Ok(DnsRCode::DSOTypeNI),
        _ => Err("Invalid RCode"),
    }?;

    Ok(DnsFlags{
        qr_bit,
        opcode,
        aa_bit,
        tc_bit,
        rd_bit,
        ra_bit,
        ad_bit,
        cd_bit,
        rcode,
    })
}

// *** TESTS ***

#[cfg(test)]
mod tests {
    use crate::dns;

    #[test]
    fn u16_parse_works() {
        assert_eq!(66, dns::parse_big_endian_bytes_to_u16(&[0x00u8, 0x42u8]));
        assert_eq!(6025, dns::parse_big_endian_bytes_to_u16(&[0x17u8, 0x89u8]));
        assert_eq!(32902, dns::parse_big_endian_bytes_to_u16(&[0x80u8, 0x86u8]));
    }
}
