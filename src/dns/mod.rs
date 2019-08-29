pub mod structs;
mod names;

// *** PUBLIC FUNCTIONS ***
pub fn nx_answer_from_query(packet: &structs::DnsPacket) -> structs::DnsPacket {
    let id = packet.id;
    let flags = structs::DnsFlags {
        qr_bit: true,
        opcode: packet.flags.opcode.to_owned(),
        aa_bit: false,
        tc_bit: false,
        rd_bit: packet.flags.rd_bit,
        ra_bit: false,
        ad_bit: false,
        cd_bit: false,
        rcode: structs::DnsRCode::NXDomain,
    };

    let questions = packet.questions.to_owned();
    let answers = Vec::<structs::DnsResourceRecord>::new();
    let nameservers = Vec::<structs::DnsResourceRecord>::new();
    let addl_recs = Vec::<structs::DnsResourceRecord>::new();

    structs::DnsPacket {
        id,
        flags,
        questions,
        answers,
        nameservers,
        addl_recs,
    }
}
