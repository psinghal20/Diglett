use diglett::*;
use std::net::UdpSocket;
use eyre::Result;

fn main() -> Result<()> {
    let qname = "psinghal20.github.io".to_string();
    let q_type = QueryType::A;
    let server = ("8.8.8.8", 53);

    let socket = UdpSocket::bind(("0.0.0.0", 9999))?;
    let mut dns_packet = DNSPacket::new();
    dns_packet.header.id = 6996;
    dns_packet.header.recur_desired = true;
    dns_packet.add_question(DNSQuestion::new(qname, q_type));
    let mut req_buf = PacketBuffer::new();

    dns_packet.write(&mut req_buf)?;

    socket.send_to(&req_buf.buf[0..req_buf.pos()], server)?;

    let mut res_buf = PacketBuffer::new();
    socket.recv_from(&mut res_buf.buf)?;
    let res_packet = DNSPacket::from_buffer(&mut res_buf)?;

    println!("DNS Header: {:#?}", res_packet.header);

    for ques in res_packet.questions {
        println!("{:#?}", ques);
    }

    for record in res_packet.answers {
        println!("{:#?}", record);
    }

    for record in res_packet.authority {
        println!("{:#?}", record);
    }
    for record in res_packet.addtional {
        println!("{:#?}", record);
    }
    Ok(())
}
