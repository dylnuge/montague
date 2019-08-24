// Reference RFC 1035 ( https://tools.ietf.org/html/rfc1035) and a bajillion
// others that have made updates to it. I've put comments where the element
// isn't coming directly from RFC 1035. RFC 6985 summarizes some updates too.
// See: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml

// *** STRUCTURES AND ENUMS ***

#[allow(dead_code)]
#[derive(PartialEq, Debug)]
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
#[derive(PartialEq, Debug)]
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
#[derive(PartialEq, Debug)]
pub struct DnsQuestion {
    // A QName is split up as a series of labels. For instance, the FQDN
    // "blog.example.com." contains three labels, "blog", "example", and "com".
    // We could store this in a number of different ways internally; for now I'm
    // going with a vector of strings which represents the labels in order.
    // e.g. "blog.example.com." would be `vec!["blog", "example", "com"]`.
    qname: Vec::<String>,
    // The type of records desired. In general, this is an RRType; there are
    // some RRTypes (like ANY) which are only valid in queries and not actual
    // resource records.
    qtype: DnsRRType,
    // The class of records desired, which is nearly always IN for internet.
    // Feels like a waste of a 16 bit int; probably this was intended for some
    // grander purpose long ago.
    qclass: DnsClass,
}

#[allow(dead_code)]
#[derive(PartialEq, Debug)]
pub struct DnsResourceRecord {
    // TODO(dylan): implement
}

#[allow(dead_code)]
#[derive(PartialEq, Debug)]
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
#[derive(PartialEq, Debug)]
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

#[allow(dead_code)]
#[derive(PartialEq, Debug)]
pub enum DnsRRType {
    // There are a lot of these: I've copied them from the IANA list
    // programmatically, but we'll focus on the most common records to implement
    // first: A (IPv4), AAAA (IPv6), CNAME, NS, MX, TXT, SOA, PTR

    // 1: A - IPv4 Host Address
    A,
    // 2: NS - Authoritative nameserver
    NS,
    // 3: MD - a mail destination (OBSOLETE - use MX)
    MD,
    // 4: MF - a mail forwarder (OBSOLETE - use MX)
    MF,
    // 5: CNAME - the canonical name for an alias
    CNAME,
    // 6: SOA - marks the start of a zone of authority
    SOA,
    // 7: MB - a mailbox domain name (EXPERIMENTAL)
    MB,
    // 8: MG - a mail group member (EXPERIMENTAL)
    MG,
    // 9: MR - a mail rename domain name (EXPERIMENTAL)
    MR,
    // 10: NULL - a null RR (EXPERIMENTAL)
    NULL,
    // 11: WKS - a well known service description
    WKS,
    // 12: PTR - a domain name pointer
    PTR,
    // 13: HINFO - host information
    HINFO,
    // 14: MINFO - mailbox or mail list information
    MINFO,
    // 15: MX - mail exchange
    MX,
    // 16: TXT - text strings
    TXT,
    // 17: RP - for Responsible Person
    RP,
    // 18: AFSDB - for AFS Data Base location
    AFSDB,
    // 19: X25 - for X.25 PSDN address
    X25,
    // 20: ISDN - for ISDN address
    ISDN,
    // 21: RT - for Route Through
    RT,
    // 22: NSAP - for NSAP address, NSAP style A record
    NSAP,
    // 23: NSAP-PTR - for domain name pointer, NSAP style
    NSAPPTR,
    // 24: SIG - for security signature
    SIG,
    // 25: KEY - for security key
    KEY,
    // 26: PX - X.400 mail mapping information
    PX,
    // 27: GPOS - Geographical Position
    GPOS,
    // 28: AAAA - IPv6 Address
    AAAA,
    // 29: LOC - Location Information
    LOC,
    // 30: NXT - Next Domain (OBSOLETE)
    NXT,
    // 31: EID - Endpoint Identifier
    EID,
    // 32: NIMLOC - Nimrod Locator
    NIMLOC,
    // 33: SRV - Server Selection
    SRV,
    // 34: ATMA - ATM Address
    ATMA,
    // 35: NAPTR - Naming Authority Pointer
    NAPTR,
    // 36: KX - Key Exchanger
    KX,
    // 37: CERT - CERT
    CERT,
    // 38: A6 - A6 (OBSOLETE - use AAAA)
    A6,
    // 39: DNAME - DNAME
    DNAME,
    // 40: SINK - SINK
    SINK,
    // 41: OPT - OPT
    OPT,
    // 42: APL - APL
    APL,
    // 43: DS - Delegation Signer
    DS,
    // 44: SSHFP - SSH Key Fingerprint
    SSHFP,
    // 45: IPSECKEY - IPSECKEY
    IPSECKEY,
    // 46: RRSIG - RRSIG
    RRSIG,
    // 47: NSEC - NSEC
    NSEC,
    // 48: DNSKEY - DNSKEY
    DNSKEY,
    // 49: DHCID - DHCID
    DHCID,
    // 50: NSEC3 - NSEC3
    NSEC3,
    // 51: NSEC3PARAM - NSEC3PARAM
    NSEC3PARAM,
    // 52: TLSA - TLSA
    TLSA,
    // 53: SMIMEA - S/MIME cert association
    SMIMEA,
    // 54: Unassigned
    // 55: HIP - Host Identity Protocol
    HIP,
    // 56: NINFO - NINFO
    NINFO,
    // 57: RKEY - RKEY
    RKEY,
    // 58: TALINK - Trust Anchor LINK
    TALINK,
    // 59: CDS - Child DS
    CDS,
    // 60: CDNSKEY - DNSKEY(s) the Child wants reflected in DS
    CDNSKEY,
    // 61: OPENPGPKEY - OpenPGP Key
    OPENPGPKEY,
    // 62: CSYNC - Child-To-Parent Synchronization
    CSYNC,
    // 63: ZONEMD - message digest for DNS zone
    ZONEMD,
    // 64-98: Unassigned
    // 99: SPF
    SPF,
    // 100: UINFO
    UINFO,
    // 101: UID
    UID,
    // 102: GID
    GID,
    // 103: UNSPEC
    UNSPEC,
    // 104: NID
    NID,
    // 105: L32
    L32,
    // 106: L64
    L64,
    // 107: LP
    LP,
    // 108: EUI48 - an EUI-48 address
    EUI48,
    // 109: EUI64 - an EUI-64 address
    EUI64,
    // 110-248: Unassigned
    // 249: TKEY - Transaction Key
    TKEY,
    // 250: TSIG - Transaction Signature
    TSIG,
    // 251: IXFR - incremental transfer
    IXFR,
    // 252: AXFR - transfer of an entire zone
    AXFR,
    // 253: MAILB - mailbox-related RRs (MB, MG or MR)
    MAILB,
    // 254: MAILA - mail agent RRs (OBSOLETE - see MX)
    MAILA,
    // 255: ANY - A request for some or all records the server has available
    ANY,
    // 256: URI - URI
    URI,
    // 257: CAA - Certification Authority Restriction
    CAA,
    // 258: AVC - Application Visibility and Control
    AVC,
    // 259: DOA - Digital Object Architecture
    DOA,
    // 260: AMTRELAY - Automatic Multicast Tunneling Relay
    AMTRELAY,
    // 261-32767: Unassigned
    // 32768: TA - DNSSEC Trust Authorities
    TA,
    // 32769: DLV - DNSSEC Lookaside Validation
    DLV,
    // 32770-65279: Unassigned
    // 65280-65534: Private Use
    // 65535: Reserved
}

#[allow(dead_code)]
#[derive(PartialEq, Debug)]
pub enum DnsClass {
    // 0: Reserved (RFC 6895)
    // 1: INternet - Basically the only actually used DNS Class
    IN,
    // 2: CSnet - Obsolete when the DNS standard was published and not even
    //    listed by IANA.
    CS,
    // 3: CHaos - IANA has this listed, but they cite a paper, not an RFC.
    CH,
    // 4: HeSiod - Same deal as CHaos.
    HS,
    // 254: NONE - Used to differentiate nonexistant RRsets from empty
    //      (zero-length) ones in Update operations. (RFC 2136)
    NONE,
    // 255: ANY - Only valid in queries, means that the client is asking for any
    //      DNS records regardless of class.
    ANY,
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

    // The header was 12 bytes, we now begin reading the rest of the packet.
    // These components are variable length (thanks to how labels are encoded)
    let mut pos: usize = 12;
    for _ in 0..qd_count {
        let (qname, new_pos) = read_name_at(&packet_bytes, pos);
        let qtype_num = parse_big_endian_bytes_to_u16(&packet_bytes[new_pos..new_pos+2]);
        let qclass_num = parse_big_endian_bytes_to_u16(&packet_bytes[new_pos+2..new_pos+4]);
        pos = new_pos + 4;

        let question = DnsQuestion {
            qname: qname,
            qtype: DnsRRType::A,
            qclass: DnsClass::IN,
        };

        questions.push(question);
    }

    Ok(DnsPacket{
        id, flags, qd_count, an_count, ns_count,
        ar_count, questions, answers, ns_records, addl_records,
    })
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

// Unlike the other functions, `bytes` here must be the WHOLE dns packet,
// because labels can contain pointers to back earlier in the packet.
// TODO(dylan): this feels a lot less clean and breaks the consistency of these
// private functions. I'm not sure what a good design is here yet; considered
// using a map for the label pointers but there's complications with that idea
fn read_name_at(bytes: &[u8], start: usize) -> (Vec::<String>, usize) {
    // TODO: This function doesn't handle malformed packets yet
    let mut labels = Vec::new();
    let mut pos = start;
    loop {
        let len_byte = bytes[pos];
        // If the length begins with the bits 11, it is a pointer
        // If it begins with the bits 00, it is a length
        // Otherwise, it is invalid
        match (len_byte >> 6) & 0b11u8 {
            0b11 => {
                // The pointer includes the lower 6 bits of the "length" and
                // the entirety of the next byte
                let pointer_start: usize =
                    (((len_byte & 0b111111u8) as usize) << 8) +
                    (bytes[pos+1] as usize);

                // We don't care where the other name ends, just what is there
                let (mut remainder, _) = read_name_at(bytes, pointer_start);
                labels.append(&mut remainder);

                // A pointer always is the end of a label; we can advance the
                // position by the two bytes we've read and return.
                pos += 2;
                break;
            }
            0b00 => {
                // Read the next `len_byte` bytes as a label
                let length = len_byte as usize;
                pos += 1;
                if length == 0 {
                    // When we reach a label of length zero, we're done reading
                    // the name
                    break
                }
                // TODO the spec is kind of annoying here. It talks a lot about
                // ASCII but doesn't ever require a domain is made of only ASCII
                // characters; UTF-8 domains exist in practice. Further, it
                // talks about "case insensitivity" but then seems to suggest
                // that if _any_ byte is not alphanumeric ASCII that's out the
                // window. Let's treat it as a case sensitive UTF-8 string for
                // now.
                let label = String::from_utf8(bytes[pos..pos+length].to_vec())
                    .expect("Label was not UTF-8");
                labels.push(label);
                pos += length;
            }
            _ => {
                // TODO ERROR HANDLING
                break;
            }
        }
    }
    (labels, pos)
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

    #[test]
    fn flags_parse_works() {
        let flag_bytes = [0x01u8, 0x20u8];
        let expected = dns::DnsFlags {
            qr_bit: false,
            opcode: dns::DnsOpcode::Query,
            aa_bit: false,
            tc_bit: false,
            rd_bit: true,
            ra_bit: false,
            ad_bit: true,
            cd_bit: false,
            rcode: dns::DnsRCode::NoError,
        };
        let result = dns::parse_dns_flags(&flag_bytes).expect("Unexpected error");
        assert_eq!(expected, result);

        let flag_bytes = [0xacu8, 0x23u8];
        let expected = dns::DnsFlags {
            qr_bit: true,
            opcode: dns::DnsOpcode::Update,
            aa_bit: true,
            tc_bit: false,
            rd_bit: false,
            ra_bit: false,
            ad_bit: true,
            cd_bit: false,
            rcode: dns::DnsRCode::NXDomain,
        };
        let result = dns::parse_dns_flags(&flag_bytes).expect("Unexpected error");
        assert_eq!(expected, result);
    }

    #[test]
    fn name_read_works() {
        // Using the example in RFC1035 to demonstrate both my code works how I
        // think it does and my comprehension of how it's supposed to work.

        // Initalize our example "packet" with 0x00s. We don't care about the
        // values outside where our labels live.
        let mut packet = [0x00u8; 93];
        // First label starting at byte 20 is f.isi.arpa
        packet[20] = 1;
        packet[21] = 'f' as u8;
        packet[22] = 3;
        packet[23] = 'i' as u8;
        packet[24] = 's' as u8;
        packet[25] = 'i' as u8;
        packet[26] = 4;
        packet[27] = 'a' as u8;
        packet[28] = 'r' as u8;
        packet[29] = 'p' as u8;
        packet[30] = 'a' as u8;
        packet[31] = 0;

        // Second label starting at byte 40 is foo.f.isi.arpa
        packet[40] = 3;
        packet[41] = 'f' as u8;
        packet[42] = 'o' as u8;
        packet[43] = 'o' as u8;
        // Pointer to "f.isi.arpa" at byte 20
        packet[44] = 0b11000000;
        packet[45] = 20;

        // Third label at byte 64 is .arpa, pointer to byte 26
        packet[64] = 0b11000000;
        packet[65] = 26;

        // Fourth label at byte 92 is just the root
        packet[92] = 0;

        let (labels, pos) = dns::read_name_at(&packet, 20);
        assert_eq!(labels, vec!["f", "isi", "arpa"]);
        assert_eq!(pos, 32);

        let (labels, pos) = dns::read_name_at(&packet, 40);
        assert_eq!(labels, vec!["foo", "f", "isi", "arpa"]);
        assert_eq!(pos, 46);

        let (labels, pos) = dns::read_name_at(&packet, 64);
        assert_eq!(labels, vec!["arpa"]);
        assert_eq!(pos, 66);

        let (labels, pos) = dns::read_name_at(&packet, 92);
        assert_eq!(labels, Vec::<String>::new());
        assert_eq!(pos, 93);
    }
}
