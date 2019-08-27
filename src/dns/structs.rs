use num_derive::FromPrimitive;

// Reference RFC 1035 ( https://tools.ietf.org/html/rfc1035) and a bajillion
// others that have made updates to it. I've put comments where the element
// isn't coming directly from RFC 1035. RFC 6985 summarizes some updates too.
// See: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml

// *** STRUCTURES AND ENUMS ***

#[allow(dead_code)]
#[derive(Clone, PartialEq, Debug)]
pub struct DnsPacket {
    // DNS transaction ID is a 16 bit number. It's arbitrary when transmitted
    // and copied into the reply so the client knows which replies correspond
    // to which requests if it's asking the same DNS server multiple questions.
    pub id: u16,
    // 16 more bits for flags which tell us a lot about the DNS packet.
    pub flags: DnsFlags,
    // u16 for number of: questions (QDCOUNT), answers (ANCOUNT), nameserver
    // records (NSCOUNT), and additional records (ARCOUNT), followed by each
    // of those segments in order
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsResourceRecord>,
    pub ns_records: Vec<DnsResourceRecord>,
    pub addl_records: Vec<DnsResourceRecord>,
}

#[allow(dead_code)]
#[derive(Clone, PartialEq, Debug)]
pub struct DnsFlags {
    // Query/Response: True if this is a response, false if it is a query
    pub qr_bit: bool,
    // Opcode: A four bit field indicating the DNS operation being performed
    pub opcode: DnsOpcode,
    // Authoritative Answer: True if this is a response from the server that
    // is the authority for the domain being queried, false otherwise.
    pub aa_bit: bool,
    // TrunCation: True if the message was truncated for being too long
    pub tc_bit: bool,
    // Recursion Desired: True if query wants nameserver to resolve this
    // request recursively, false if not. Copied into the response.
    pub rd_bit: bool,
    // Recursion Available: True if this is a response from a server that
    // supports recursion, false if response is from a server that does not,
    // undefined/ignored in a query
    pub ra_bit: bool,
    // The next bit is the Z field, which is reserved and should be zero. We
    // don't need it in the struct

    // TODO(dylan): Better understand/document next two DNSSEC flags
    // Authenticated Data: Part of DNSSEC (RFC 2535, 4035 and others). Indicates
    // that DNSSEC was used to authenticate all responses. Only relevant when
    // communicating with trusted nameservers.
    pub ad_bit: bool,
    // Checking Disabled: Also DNSSEC (RFC 2535, 4035 and others). Indicates
    // DNSSEC should not be used/was not used in serving this response
    pub cd_bit: bool,
    // RCode: A four bit field indicating the status of a response.
    // Undefined/ignored in queries.
    pub rcode: DnsRCode,
}

#[allow(dead_code)]
#[derive(Clone, PartialEq, Debug)]
pub struct DnsQuestion {
    // A QName is split up as a series of labels. For instance, the FQDN
    // "blog.example.com." contains three labels, "blog", "example", and "com".
    // We could store this in a number of different ways internally; for now I'm
    // going with a vector of strings which represents the labels in order.
    // e.g. "blog.example.com." would be `vec!["blog", "example", "com"]`.
    pub qname: Vec<String>,
    // The type of records desired. In general, this is an RRType; there are
    // some RRTypes (like ANY) which are only valid in queries and not actual
    // resource records.
    pub qtype: DnsRRType,
    // The class of records desired, which is nearly always IN for internet.
    // Feels like a waste of a 16 bit int; probably this was intended for some
    // grander purpose long ago.
    pub qclass: DnsClass,
}

#[allow(dead_code)]
#[derive(Clone, PartialEq, Debug)]
pub struct DnsResourceRecord {
    // See comment in DnsQuestion struct above, the first three fields here are
    // nearly identical
    pub name: Vec<String>,
    pub rr_type: DnsRRType,
    pub class: DnsClass,
    // Unsigned 32 bit integer signifying the amount of time the client can
    // cache this answer for. 0 means not to cache. Note that RFC 1035 states
    // this is signed in some sections, this is corrected in errata.
    pub ttl: u32,
    // Record length: tells us how long the data in record data is
    pub rd_length: u16,
    // Record data: variably interpreted depending on RR type. For now, just
    // store it as a byte vector
    pub record: Vec<u8>,
}

#[allow(dead_code)]
#[derive(FromPrimitive, Clone, PartialEq, Debug)]
pub enum DnsOpcode {
    // Opcode 0: standard query
    Query = 0,
    // Opcode 1: inverse query (obsoleted by RFC 3425)
    IQuery = 1,
    // Opcode 2: server status request
    Status = 2,
    // 3 reserved for future use
    // Opcode 4: notify of zone change (RFC 1996)
    Zone = 4,
    // Opcode 5: dynamic update to DNS records (RFC 2136)
    Update = 5,
    // Opcode 6: DNS Stateful Operations (RFC 8490)
    DSO = 6,
    // 7-15 reserved for future use
}

#[allow(dead_code)]
#[derive(FromPrimitive, Clone, PartialEq, Debug)]
pub enum DnsRCode {
    // 0: No error
    NoError = 0,
    // 1: Format error - NS couldn't interpret query
    FormError = 1,
    // 2: Server failure - NS couldn't process query
    ServFail = 2,
    // 3: Name error - The domain does not exist
    NXDomain = 3,
    // 4: Not Implemented - The requested operation can't be done by this NS
    NotImp = 4,
    // 5: Refused - Namserver refused operation for an unspecified reason
    Refused = 5,
    // TODO(dylan): document what 6-11 actually mean
    YXDomain = 6,
    YXRRSet = 7,
    NXRRSet = 8,
    NotAuth = 9,
    NotZone = 10,
    DSOTypeNI = 11,
    // 12-15 are reserved
    // TODO(dylan): RCodes above 16 are defined but only for use in records,
    // since the RCode field in the header is too short to store numbers that
    // high. Add those here. (RFC 2929 explicitly discusses this, various other
    // RFCs implement them)
}

#[allow(dead_code)]
#[derive(FromPrimitive, Clone, PartialEq, Debug)]
pub enum DnsRRType {
    // There are a lot of these: I've copied them from the IANA list
    // programmatically, but we'll focus on the most common records to implement
    // first: A (IPv4), AAAA (IPv6), CNAME, NS, MX, TXT, SOA, PTR

    // 1: A - IPv4 Host Address
    A = 1,
    // 2: NS - Authoritative nameserver
    NS = 2,
    // 3: MD - a mail destination (OBSOLETE - use MX)
    MD = 3,
    // 4: MF - a mail forwarder (OBSOLETE - use MX)
    MF = 4,
    // 5: CNAME - the canonical name for an alias
    CNAME = 5,
    // 6: SOA - marks the start of a zone of authority
    SOA = 6,
    // 7: MB - a mailbox domain name (EXPERIMENTAL)
    MB = 7,
    // 8: MG - a mail group member (EXPERIMENTAL)
    MG = 8,
    // 9: MR - a mail rename domain name (EXPERIMENTAL)
    MR = 9,
    // 10: NULL - a null RR (EXPERIMENTAL)
    NULL = 10,
    // 11: WKS - a well known service description
    WKS = 11,
    // 12: PTR - a domain name pointer
    PTR = 12,
    // 13: HINFO - host information
    HINFO = 13,
    // 14: MINFO - mailbox or mail list information
    MINFO = 14,
    // 15: MX - mail exchange
    MX = 15,
    // 16: TXT - text strings
    TXT = 16,
    // 17: RP - for Responsible Person
    RP = 17,
    // 18: AFSDB - for AFS Data Base location
    AFSDB = 18,
    // 19: X25 - for X.25 PSDN address
    X25 = 19,
    // 20: ISDN - for ISDN address
    ISDN = 20,
    // 21: RT - for Route Through
    RT = 21,
    // 22: NSAP - for NSAP address, NSAP style A record
    NSAP = 22,
    // 23: NSAP-PTR - for domain name pointer, NSAP style
    NSAPPTR = 23,
    // 24: SIG - for security signature
    SIG = 24,
    // 25: KEY - for security key
    KEY = 25,
    // 26: PX - X.400 mail mapping information
    PX = 26,
    // 27: GPOS - Geographical Position
    GPOS = 27,
    // 28: AAAA - IPv6 Address
    AAAA = 28,
    // 29: LOC - Location Information
    LOC = 29,
    // 30: NXT - Next Domain (OBSOLETE)
    NXT = 30,
    // 31: EID - Endpoint Identifier
    EID = 31,
    // 32: NIMLOC - Nimrod Locator
    NIMLOC = 32,
    // 33: SRV - Server Selection
    SRV = 33,
    // 34: ATMA - ATM Address
    ATMA = 34,
    // 35: NAPTR - Naming Authority Pointer
    NAPTR = 35,
    // 36: KX - Key Exchanger
    KX = 36,
    // 37: CERT - CERT
    CERT = 37,
    // 38: A6 - A6 (OBSOLETE - use AAAA)
    A6 = 38,
    // 39: DNAME - DNAME
    DNAME = 39,
    // 40: SINK - SINK
    SINK = 40,
    // 41: OPT - OPT
    OPT = 41,
    // 42: APL - APL
    APL = 42,
    // 43: DS - Delegation Signer
    DS = 43,
    // 44: SSHFP - SSH Key Fingerprint
    SSHFP = 44,
    // 45: IPSECKEY - IPSECKEY
    IPSECKEY = 45,
    // 46: RRSIG - RRSIG
    RRSIG = 46,
    // 47: NSEC - NSEC
    NSEC = 47,
    // 48: DNSKEY - DNSKEY
    DNSKEY = 48,
    // 49: DHCID - DHCID
    DHCID = 49,
    // 50: NSEC3 - NSEC3
    NSEC3 = 50,
    // 51: NSEC3PARAM - NSEC3PARAM
    NSEC3PARAM = 51,
    // 52: TLSA - TLSA
    TLSA = 52,
    // 53: SMIMEA - S/MIME cert association
    SMIMEA = 53,
    // 54: Unassigned
    // 55: HIP - Host Identity Protocol
    HIP = 55,
    // 56: NINFO - NINFO
    NINFO = 56,
    // 57: RKEY - RKEY
    RKEY = 57,
    // 58: TALINK - Trust Anchor LINK
    TALINK = 58,
    // 59: CDS - Child DS
    CDS = 59,
    // 60: CDNSKEY - DNSKEY(s) the Child wants reflected in DS
    CDNSKEY = 60,
    // 61: OPENPGPKEY - OpenPGP Key
    OPENPGPKEY = 61,
    // 62: CSYNC - Child-To-Parent Synchronization
    CSYNC = 62,
    // 63: ZONEMD - message digest for DNS zone
    ZONEMD = 63,
    // 64-98: Unassigned
    // 99: SPF
    SPF = 99,
    // 100: UINFO
    UINFO = 100,
    // 101: UID
    UID = 101,
    // 102: GID
    GID = 102,
    // 103: UNSPEC
    UNSPEC = 103,
    // 104: NID
    NID = 104,
    // 105: L32
    L32 = 105,
    // 106: L64
    L64 = 106,
    // 107: LP
    LP = 107,
    // 108: EUI48 - an EUI-48 address
    EUI4 = 108,
    // 109: EUI64 - an EUI-64 address
    EUI64 = 109,
    // 110-248: Unassigned
    // 249: TKEY - Transaction Key
    TKEY = 249,
    // 250: TSIG - Transaction Signature
    TSIG = 250,
    // 251: IXFR - incremental transfer
    IXFR = 251,
    // 252: AXFR - transfer of an entire zone
    AXF = 252,
    // 253: MAILB - mailbox-related RRs (MB, MG or MR)
    MAILB = 253,
    // 254: MAILA - mail agent RRs (OBSOLETE - see MX)
    MAILA = 254,
    // 255: ANY - A request for some or all records the server has available
    ANY = 255,
    // 256: URI - URI
    URI = 256,
    // 257: CAA - Certification Authority Restriction
    CAA = 257,
    // 258: AVC - Application Visibility and Control
    AVC = 258,
    // 259: DOA - Digital Object Architecture
    DOA = 259,
    // 260: AMTRELAY - Automatic Multicast Tunneling Relay
    AMTRELAY = 260,
    // 261-32767: Unassigned
    // 32768: TA - DNSSEC Trust Authorities
    TA = 32768,
    // 32769: DLV - DNSSEC Lookaside Validation
    DLV = 32769,
    // 32770-65279: Unassigned
    // 65280-65534: Private Use
    // 65535: Reserved
}

#[allow(dead_code)]
#[derive(FromPrimitive, Clone, PartialEq, Debug)]
pub enum DnsClass {
    // 0: Reserved (RFC 6895)
    // 1: INternet - Basically the only actually used DNS Class
    IN = 1,
    // 2: CSnet - Obsolete when the DNS standard was published and not even
    //    listed by IANA.
    CS = 2,
    // 3: CHaos - IANA has this listed, but they cite a paper, not an RFC.
    CH = 3,
    // 4: HeSiod - Same deal as CHaos.
    HS = 4,
    // 254: NONE - Used to differentiate nonexistant RRsets from empty
    //      (zero-length) ones in Update operations. (RFC 2136)
    NONE = 254,
    // 255: ANY - Only valid in queries, means that the client is asking for any
    //      DNS records regardless of class.
    ANY = 255,
}
