// Reference RFC 1035 ( https://tools.ietf.org/html/rfc1035) and a bajillion
// others that have made updates to it. I've put comments where the element
// isn't coming directly from RFC 1035.
// See: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
struct DnsPacket {
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

struct DnsFlags {
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
    // The next bit is the Z field, which is reserved and should be zero.
    z: bool,
    // TODO(dylan): Better understand/document next two DNSSEC flags
    // Authenticated Data: Part of DNSSEC (RFC 4035 and others). Indicates that
    // DNSSEC was used to authenticate all responses. Only relevant when
    // communicating with trusted nameservers.
    ad_bit: bool,
    // Checking Disabled: Also DNSSEC (RFC 4035 and others). Indicates DNSSEC
    // should not be used/was not used in serving this response
    cd_bit: bool,
    // RCode: A four bit field indicating the status of a response.
    // Undefined/ignored in queries.
    rcode: DnsRCode
}

struct DnsQuestion {
    // TODO(dylan): implement
}

struct DnsResourceRecord {
    // TODO(dylan): implement
}

enum DnsOpcode {
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

enum DnsRCode {
    // 0: No error
    NoError,
    // 1: Format error - NS couldn't interpret query
    FormError,
    // 2: Server failure - NS couldn't process query
    ServFail,
    // 3: NX Domain - The domain does not exist
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

