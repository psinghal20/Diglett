use diglett::*;
use std::net;
use std::{thread, time};
use std::net::{Ipv4Addr, SocketAddr};
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

#[derive(Debug)]
struct DNSUdpServer {
    tokio_socket: UdpSocket,
    std_socket: net::UdpSocket,
}

impl DNSUdpServer {
    async fn new(addr: (&str, u16)) -> Result<DNSUdpServer> {
        let std_socket = net::UdpSocket::bind(addr)?;
        let tokio_socket = UdpSocket::from_std(std_socket.try_clone()?)?;
        Ok(DNSUdpServer {
            tokio_socket,
            std_socket
        })
    }

    async fn run_server<'a>(&'a mut self) -> Result<()> {
        loop {
            let mut req_buffer = PacketBuffer::new();
            // let socket_clone = self.socket.clone();
            let src = match self.tokio_socket.recv_from(&mut req_buffer.buf).await {
                Ok((_, src)) => src,
                Err(e) => {
                    println!("Failed to read from UDP Socket: {}", e);
                    continue;
                }
            };
            let std_socket_clone = self.std_socket.try_clone()?;
            tokio::spawn(async move {
                if let Err(err) = DNSUdpServer::handle_request(std_socket_clone, req_buffer, src).await {
                    println!("Failed to handle request from src {} : {}", src, err);
                }
            });
        }
    }

    async fn handle_request(socket: net::UdpSocket, mut req_buffer: PacketBuffer, src: SocketAddr) -> Result<()>{
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
        tokio::task::spawn_blocking(move || {
            thread::sleep(time::Duration::from_millis(10000));
            if let Err(e) = socket.send_to(&res_buffer.buf[0..len], src) {
                println!("Failed to send response to {} : {}", src, e);
            }
        }).await?;
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut server = DNSUdpServer::new(("0.0.0.0", 2053)).await?;
    server.run_server().await?;
    Ok(())
}
