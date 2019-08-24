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
    pub id: u16,
    // 16 more bits for flags which tell us a lot about the DNS packet.
    pub flags: DnsFlags,
    // u16 for number of: questions (QDCOUNT), answers (ANCOUNT), nameserver
    // records (NSCOUNT), and additional records (ARCOUNT)
    pub qd_count: u16,
    pub an_count: u16,
    pub ns_count: u16,
    pub ar_count: u16,
    // And the actual records themselves
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsResourceRecord>,
    pub ns_records: Vec<DnsResourceRecord>,
    pub addl_records: Vec<DnsResourceRecord>,
}

#[allow(dead_code)]
#[derive(PartialEq, Debug)]
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
#[derive(PartialEq, Debug)]
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
