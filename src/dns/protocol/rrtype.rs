use num_derive::FromPrimitive;

#[allow(dead_code)]
#[derive(FromPrimitive, Clone, Copy, PartialEq, Debug)]
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
