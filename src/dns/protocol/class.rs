#[allow(dead_code)]
#[derive(Clone, PartialEq, Debug)]
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
    // RFC 6891 defines the OPT "Pesudo-RR", which overloads the class header
    //      to contain the requestor's UDP payload size
    EdnsPayloadSize(u16),
}

impl DnsClass {
    pub fn from_u16(class: u16) -> Option<DnsClass> {
        match class {
            1 => Some(DnsClass::IN),
            2 => Some(DnsClass::CS),
            3 => Some(DnsClass::CH),
            4 => Some(DnsClass::HS),
            254 => Some(DnsClass::NONE),
            255 => Some(DnsClass::ANY),
            _ => None,
        }
    }

    pub fn to_u16(&self) -> u16 {
        match self {
            DnsClass::IN => 1,
            DnsClass::CS => 2,
            DnsClass::CH => 3,
            DnsClass::HS => 4,
            DnsClass::NONE => 254,
            DnsClass::ANY => 255,
            // On an EDNS packet, the "class" is a payload size
            DnsClass::EdnsPayloadSize(payload) => payload.to_owned(),
        }
    }
}
