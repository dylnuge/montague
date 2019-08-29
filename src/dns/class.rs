use num_derive::FromPrimitive;

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
