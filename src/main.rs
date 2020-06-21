use diglett::*;
use std::net::Ipv4Addr;
use tokio::net::UdpSocket;
use futures::future::BoxFuture;
use eyre::Result;

async fn lookup(qname: &str, q_type: QueryType, server: (Ipv4Addr, u16)) -> Result<DNSPacket> {
    let mut socket = UdpSocket::bind(("0.0.0.0", 9999)).await?;
    let mut dns_packet = DNSPacket::new();
    dns_packet.header.id = 6996;
    dns_packet.header.recur_desired = true;
    dns_packet.add_question(DNSQuestion::new(qname.to_owned(), q_type));
    let mut req_buf = PacketBuffer::new();

    dns_packet.write(&mut req_buf)?;

    socket.send_to(&req_buf.buf[0..req_buf.pos()], server).await?;

    let mut res_buf = PacketBuffer::new();
    socket.recv_from(&mut res_buf.buf).await?;
    let res_packet = DNSPacket::from_buffer(&mut res_buf)?;
    Ok(res_packet)
}

fn recursive_lookup(qname: &'_ str, q_type: QueryType) -> BoxFuture<'_, Result<DNSPacket>> {
    Box::pin(async move {
        let mut ns = "198.41.0.4".parse::<Ipv4Addr>()?;

        loop {
            println!("attempting lookup of {:?} {} with ns {}", q_type, qname, ns);

            let server = (ns.clone(), 53);

            let response = lookup(qname, q_type, server).await?;

            if !response.answers.is_empty() && response.header.res_code == RCode::NOERROR {
                return Ok(response);
            }

            if response.header.res_code == RCode::NXDOMAIN {
                return Ok(response);
            }

            if let Some(new_ns) = response.get_resolved_ns(qname) {
                ns = new_ns;
                continue;
            }

            let new_ns_name = match response.get_unresolved_ns(qname) {
                Some(name) => name,
                None => return Ok(response),
            };

            let recursive_response = recursive_lookup(new_ns_name, QueryType::A).await?;

            if let Some(new_ns) = recursive_response.get_random_a() {
                ns = new_ns;
            } else {
                return Ok(response);
            }
        }
    })
}

async fn handle_request(socket: &mut UdpSocket) -> Result<()> {
    let mut req_buffer = PacketBuffer::new();

    let (_, src) = socket.recv_from(&mut req_buffer.buf).await?;

    let mut request_packet = DNSPacket::from_buffer(&mut req_buffer)?;

    let mut res_packet = DNSPacket::new();

    res_packet.header.id = request_packet.header.id;
    res_packet.header.recur_desired = request_packet.header.recur_desired;
    res_packet.header.recur_available = true;
    res_packet.header.query_response = true;
    if let Some(question) = request_packet.questions.pop() {
        println!("Recieved Question: {:?}", question);

        if let Ok(result) = recursive_lookup(&question.name, question.q_type).await {
            res_packet.questions.push(question);
            res_packet.header.res_code = result.header.res_code;

            for rec in result.answers {
                println!("Answer: {:?}", rec);
                res_packet.answers.push(rec);
            }
            for rec in result.authority {
                println!("Authority: {:?}", rec);
                res_packet.authority.push(rec);
            }
            for rec in result.addtional {
                println!("Resource: {:?}", rec);
                res_packet.addtional.push(rec);
            }
        } else {
            res_packet.header.res_code = RCode::SERVFAIL;
        }
    } else {
        res_packet.header.res_code = RCode::FORMERR;
    }

    let mut res_buffer = PacketBuffer::new();
    res_packet.write(&mut res_buffer)?;
    let len = res_buffer.pos();
    socket.send_to(&res_buffer.buf[0..len], src).await?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut socket = UdpSocket::bind(("0.0.0.0", 2053)).await?;

    // For now, queries are handled sequentially, so an infinite loop for servicing
    // requests is initiated.
    loop {
        match handle_request(&mut socket).await {
            Ok(_) => {},
            Err(e) => eprintln!("An error occured: {}", e),
        }
    }
}
