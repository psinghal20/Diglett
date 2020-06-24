use buffer::{ArrayBuffer, PacketBufferTrait, VecBuffer};
use diglett::*;
use eyre::Result;
use futures::future::BoxFuture;
use std::net;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

async fn udp_lookup(qname: &str, q_type: QueryType, server: (Ipv4Addr, u16)) -> Result<DNSPacket> {
    let mut socket = UdpSocket::bind(("0.0.0.0", 9999)).await?;
    let mut dns_packet = DNSPacket::new();
    dns_packet.header.id = 6996;
    dns_packet.header.recur_desired = true;
    dns_packet.add_question(DNSQuestion::new(qname.to_owned(), q_type));
    let mut req_buf = ArrayBuffer::new();

    dns_packet.write(&mut req_buf)?;

    socket
        .send_to(&req_buf.buf[0..req_buf.pos()], server)
        .await?;

    let mut res_buf = ArrayBuffer::new();
    socket.recv_from(&mut res_buf.buf).await?;
    let res_packet = DNSPacket::from_buffer(&mut res_buf)?;
    Ok(res_packet)
}

async fn tcp_lookup(qname: &str, q_type: QueryType, server: (Ipv4Addr, u16)) -> Result<DNSPacket> {
    let mut socket = TcpStream::connect(server).await?;
    let mut dns_packet = DNSPacket::new();
    dns_packet.header.id = 6996;
    dns_packet.header.recur_desired = true;
    dns_packet.add_question(DNSQuestion::new(qname.to_owned(), q_type));
    let mut req_buf = VecBuffer::new();

    dns_packet.write(&mut req_buf)?;
    req_buf.to_socket(&mut socket).await?;

    let mut res_buf = VecBuffer::from_socket(&mut socket).await?;
    let res_packet = DNSPacket::from_buffer(&mut res_buf)?;
    Ok(res_packet)
}

fn recursive_lookup(
    qname: &'_ str,
    q_type: QueryType,
    protocol: ReqProtocol,
) -> BoxFuture<'_, Result<DNSPacket>> {
    Box::pin(async move {
        let mut ns = "198.41.0.4".parse::<Ipv4Addr>()?;

        loop {
            println!("attempting lookup of {:?} {} with ns {}", q_type, qname, ns);

            let server = (ns.clone(), 53);

            let response = match protocol {
                ReqProtocol::UDP => udp_lookup(qname, q_type, server).await?,
                ReqProtocol::TCP => tcp_lookup(qname, q_type, server).await?,
            };

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

            let recursive_response = recursive_lookup(new_ns_name, QueryType::A, protocol).await?;

            if let Some(new_ns) = recursive_response.get_random_a() {
                ns = new_ns;
            } else {
                return Ok(response);
            }
        }
    })
}

#[derive(Debug, Copy, Clone)]
enum ReqProtocol {
    UDP,
    TCP,
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
            std_socket,
        })
    }

    async fn run_server<'a>(&'a mut self) -> Result<()> {
        loop {
            let mut req_buffer = ArrayBuffer::new();
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
                if let Err(err) =
                    DNSUdpServer::handle_request(std_socket_clone, req_buffer, src).await
                {
                    println!("Failed to handle request from src {} : {}", src, err);
                }
            });
        }
    }

    async fn handle_request(
        socket: net::UdpSocket,
        mut req_buffer: ArrayBuffer,
        src: SocketAddr,
    ) -> Result<()> {
        let mut request_packet = DNSPacket::from_buffer(&mut req_buffer)?;

        let mut res_packet = DNSPacket::new();

        res_packet.header.id = request_packet.header.id;
        res_packet.header.recur_desired = request_packet.header.recur_desired;
        res_packet.header.recur_available = true;
        res_packet.header.query_response = true;
        if let Some(question) = request_packet.questions.pop() {
            println!("Recieved Question: {:?}", question);

            if let Ok(result) =
                recursive_lookup(&question.name, question.q_type, ReqProtocol::UDP).await
            {
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

        let mut res_buffer = ArrayBuffer::new();
        res_packet.write(&mut res_buffer)?;
        let len = res_buffer.pos();
        tokio::task::spawn_blocking(move || {
            if let Err(e) = socket.send_to(&res_buffer.buf[0..len], src) {
                println!("Failed to send response to {} : {}", src, e);
            }
        })
        .await?;
        Ok(())
    }
}

struct DNSTcpServer {
    listener: TcpListener,
}

impl DNSTcpServer {
    async fn new(addr: (&str, u16)) -> Result<DNSTcpServer> {
        Ok(DNSTcpServer {
            listener: TcpListener::bind(addr).await?,
        })
    }

    async fn run_server(&mut self) -> Result<()> {
        loop {
            let (mut socket, _) = self.listener.accept().await?;
            tokio::spawn(async move {
                if let Err(err) = DNSTcpServer::handle_connection(&mut socket).await {
                    eprintln!(
                        "Failed to handle request from src {} : {}",
                        socket.peer_addr().unwrap(),
                        err
                    );
                }
            });
        }
    }

    async fn handle_connection(socket: &mut TcpStream) -> Result<()> {
        let mut req_buffer = VecBuffer::from_socket(socket).await?;

        let mut request_packet = DNSPacket::from_buffer(&mut req_buffer)?;

        let mut res_packet = DNSPacket::new();

        res_packet.header.id = request_packet.header.id;
        res_packet.header.recur_desired = request_packet.header.recur_desired;
        res_packet.header.recur_available = true;
        res_packet.header.query_response = true;
        if let Some(question) = request_packet.questions.pop() {
            println!("Recieved Question: {:?}", question);

            if let Ok(result) =
                recursive_lookup(&question.name, question.q_type, ReqProtocol::TCP).await
            {
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

        let mut res_buffer = VecBuffer::new();
        res_packet.write(&mut res_buffer)?;
        res_buffer.to_socket(socket).await?;
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut udp_server = DNSUdpServer::new(("0.0.0.0", 2053)).await?;
    let udp_server_handle = tokio::spawn(async move {
        if let Err(err) = udp_server.run_server().await {
            eprintln!("Failed to start UDP server: {}", err);
        }
    });
    let mut tcp_server = DNSTcpServer::new(("0.0.0.0", 2054)).await?;
    let tcp_server_handle = tokio::spawn(async move {
        if let Err(err) = tcp_server.run_server().await {
            eprintln!("Failed to start TCP server: {}", err);
        }
    });
    let (first, second) = tokio::join!(udp_server_handle, tcp_server_handle);
    first?;
    second?;
    Ok(())
}
