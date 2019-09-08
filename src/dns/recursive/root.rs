use std::net::{IpAddr, Ipv4Addr};

// For now, this is a hardcoded list of A and AAAA records for the root nameservers
// Information from https://www.iana.org/domains/root/servers
// TODO pull this from configuration or directly from the OS
pub fn get_root_nameserver() -> IpAddr {
    // This is the A record for e.root-servers.net operated by NASA (Ames Research Center)
    // TODO this should support V6 addresses
    // TODO this should support returning any root nameserver
    IpAddr::V4(Ipv4Addr::new(192, 203, 230, 10))
}
