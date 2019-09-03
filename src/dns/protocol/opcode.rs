use num_derive::FromPrimitive;

#[allow(dead_code)]
#[derive(FromPrimitive, Copy, Clone, PartialEq, Debug)]
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
