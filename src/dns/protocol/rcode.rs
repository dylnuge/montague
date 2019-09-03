use num_derive::FromPrimitive;

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
