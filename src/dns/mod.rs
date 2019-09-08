pub mod protocol;
pub mod recursive;

// *** PUBLIC FUNCTIONS ***
// This function is a stub that should eventually be removed in favor of more robust server
// functionality
pub fn not_imp_answer_from_query(packet: &protocol::DnsPacket) -> protocol::DnsPacket {
    let id = packet.id;
    let flags = protocol::DnsFlags {
        qr_bit: true,
        aa_bit: false,
        tc_bit: false,
        ra_bit: false,
        ad_bit: false,
        cd_bit: false,
        rcode: protocol::DnsRCode::NotImp,
        ..packet.flags
    };

    let questions = packet.questions.to_owned();
    let answers = Vec::<protocol::DnsResourceRecord>::new();
    let nameservers = Vec::<protocol::DnsResourceRecord>::new();
    let addl_recs = Vec::<protocol::DnsResourceRecord>::new();

    protocol::DnsPacket {
        id,
        flags,
        questions,
        answers,
        nameservers,
        addl_recs,
    }
}
