pub mod buffer;
pub mod cache;
use buffer::*;
use eyre::Result;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RCode {
    NOERROR,
    FORMERR,
    SERVFAIL,
    NXDOMAIN,
    NOTIMP,
    REFUSED,
}

impl RCode {
    fn from_num(num: usize) -> RCode {
        match num {
            1 => RCode::FORMERR,
            2 => RCode::SERVFAIL,
            3 => RCode::NXDOMAIN,
            4 => RCode::NOTIMP,
            5 => RCode::REFUSED,
            _ => RCode::NOERROR,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DNSHeader {
    pub id: u16,
    pub query_response: bool,
    pub opcode: u8, // We only need 4 bits of these 8
    pub auth_answer: bool,
    pub truncated_msg: bool,
    pub recur_desired: bool,
    pub recur_available: bool,
    pub z_res: bool, // Actually 3 bits, ignoring them for now
    pub res_code: RCode,

    pub q_count: u16,
    pub an_count: u16,
    pub ns_count: u16,
    pub ad_count: u16,
}

impl DNSHeader {
    pub fn new() -> DNSHeader {
        DNSHeader {
            id: 0,
            query_response: false,
            opcode: 0,
            auth_answer: false,
            truncated_msg: false,
            recur_desired: false,
            recur_available: false,
            z_res: false,
            res_code: RCode::NOERROR,
            q_count: 0,
            an_count: 0,
            ns_count: 0,
            ad_count: 0,
        }
    }

    pub fn read<T: PacketBufferTrait>(&mut self, buf: &mut T) -> Result<()> {
        self.id = buf.read_u16()?;
        let flags = buf.read_u16()?;
        self.query_response = (flags & (1 << 15)) > 0;
        self.opcode = (flags >> 11) as u8 & 0xF;
        self.auth_answer = (flags & (1 << 10)) > 0;
        self.truncated_msg = (flags & (1 << 9)) > 0;
        self.recur_desired = (flags & (1 << 8)) > 0;
        self.recur_available = (flags & (1 << 7)) > 0;
        self.z_res = (flags & (7 << 4)) > 0;
        self.res_code = RCode::from_num((flags & 0xF) as usize);
        self.q_count = buf.read_u16()?;
        self.an_count = buf.read_u16()?;
        self.ns_count = buf.read_u16()?;
        self.ad_count = buf.read_u16()?;
        Ok(())
    }

    pub fn write<T: PacketBufferTrait>(&self, buf: &mut T) -> Result<()> {
        buf.write_u16(self.id)?;
        buf.write_u16(
            ((self.query_response as u16) << 15)
                | ((self.opcode as u16) << 11)
                | ((self.auth_answer as u16) << 10)
                | ((self.truncated_msg as u16) << 9)
                | ((self.recur_desired as u16) << 8)
                | ((self.recur_available as u16) << 7)
                | ((self.z_res as u16) << 4)
                | self.res_code as u16,
        )?;
        buf.write_u16(self.q_count)?;
        buf.write_u16(self.an_count)?;
        buf.write_u16(self.ns_count)?;
        buf.write_u16(self.ad_count)?;
        Ok(())
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy)]
pub enum QueryType {
    UNKNOWN(u16),
    A,
    NS,
    CNAME,
    SOA,
    MX,
    AAAA,
}

impl QueryType {
    fn to_num(&self) -> u16 {
        match *self {
            Self::UNKNOWN(code) => code,
            Self::A => 1,
            Self::NS => 2,
            Self::CNAME => 5,
            Self::SOA => 6,
            Self::MX => 15,
            Self::AAAA => 28,
        }
    }
    fn from_num(num: u16) -> Self {
        match num {
            1 => Self::A,
            2 => Self::NS,
            5 => Self::CNAME,
            6 => Self::SOA,
            15 => Self::MX,
            28 => Self::AAAA,
            _ => Self::UNKNOWN(num),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DNSQuestion {
    pub name: String,
    pub q_type: QueryType,
}

impl DNSQuestion {
    pub fn new(name: String, q_type: QueryType) -> Self {
        Self { name, q_type }
    }

    pub fn read<T: PacketBufferTrait>(buf: &mut T) -> Result<DNSQuestion> {
        let mut name = String::new();
        buf.read_qname(&mut name)?;
        let q_type = QueryType::from_num(buf.read_u16()?);
        buf.read_u16()?;
        Ok(DNSQuestion { name, q_type })
    }

    pub fn write<T: PacketBufferTrait>(&self, buf: &mut T) -> Result<()> {
        buf.write_qname(&self.name)?;
        buf.write_u16(self.q_type.to_num())?;
        buf.write_u16(1 as u16)?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum DNSRecord {
    UNKNOWN {
        name: String,
        q_type: QueryType,
        class: u16,
        ttl: u32,
        len: u16,
    },
    A {
        name: String,
        q_type: QueryType,
        class: u16,
        ttl: u32,
        len: u16,
        addr: Ipv4Addr,
    },
    NS {
        name: String,
        q_type: QueryType,
        class: u16,
        ttl: u32,
        len: u16,
        host: String,
    },
    CNAME {
        name: String,
        q_type: QueryType,
        class: u16,
        ttl: u32,
        len: u16,
        host: String,
    },
    MX {
        name: String,
        q_type: QueryType,
        class: u16,
        ttl: u32,
        len: u16,
        priority: u16,
        host: String,
    },
    AAAA {
        name: String,
        q_type: QueryType,
        class: u16,
        ttl: u32,
        len: u16,
        addr: Ipv6Addr,
    },
    SOA {
        name: String,
        q_type: QueryType,
        class: u16,
        ttl: u32,
        len: u16,
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
}

impl DNSRecord {
    pub fn get_ttl(&self) -> u32 {
        match *self {
            DNSRecord::A { ttl, .. } => ttl,
            DNSRecord::AAAA { ttl, .. } => ttl,
            DNSRecord::CNAME { ttl, .. } => ttl,
            DNSRecord::SOA { ttl, .. } => ttl,
            DNSRecord::MX { ttl, .. } => ttl,
            DNSRecord::NS { ttl, .. } => ttl, 
            DNSRecord::UNKNOWN { ttl, .. } => ttl,
        }
    }
    pub fn read<T: PacketBufferTrait>(buf: &mut T) -> Result<DNSRecord> {
        let mut domain = String::new();
        buf.read_qname(&mut domain)?;
        let q_type = QueryType::from_num(buf.read_u16()?);
        let class = buf.read_u16()?;
        let ttl = buf.read_u32()?;
        let len = buf.read_u16()?;
        match q_type {
            QueryType::A => {
                // We have a A record query
                let raw_ip = buf.read_u32()?;
                let addr = Ipv4Addr::new(
                    (raw_ip >> 24) as u8,
                    (raw_ip >> 16) as u8,
                    (raw_ip >> 8) as u8,
                    (raw_ip) as u8,
                );
                Ok(DNSRecord::A {
                    name: domain,
                    q_type: q_type,
                    class: class,
                    ttl: ttl,
                    len: len,
                    addr: addr,
                })
            }
            QueryType::NS => {
                let mut host = String::new();
                buf.read_qname(&mut host)?;
                Ok(DNSRecord::NS {
                    name: domain,
                    q_type: q_type,
                    class: class,
                    ttl: ttl,
                    len: len,
                    host: host,
                })
            }
            QueryType::CNAME => {
                let mut host = String::new();
                buf.read_qname(&mut host)?;
                Ok(DNSRecord::CNAME {
                    name: domain,
                    q_type: q_type,
                    class: class,
                    ttl: ttl,
                    len: len,
                    host: host,
                })
            }
            QueryType::MX => {
                let priority = buf.read_u16()?;
                let mut host = String::new();
                buf.read_qname(&mut host)?;
                Ok(DNSRecord::MX {
                    name: domain,
                    q_type: q_type,
                    class: class,
                    ttl: ttl,
                    len: len,
                    priority: priority,
                    host: host,
                })
            }
            QueryType::AAAA => {
                let raw_ip_1 = buf.read_u32()?;
                let raw_ip_2 = buf.read_u32()?;
                let raw_ip_3 = buf.read_u32()?;
                let raw_ip_4 = buf.read_u32()?;

                let addr = Ipv6Addr::new(
                    (raw_ip_1 >> 16) as u16,
                    (raw_ip_1) as u16,
                    (raw_ip_2 >> 16) as u16,
                    (raw_ip_2) as u16,
                    (raw_ip_3 >> 16) as u16,
                    (raw_ip_3) as u16,
                    (raw_ip_4 >> 16) as u16,
                    (raw_ip_4) as u16,
                );
                Ok(DNSRecord::AAAA {
                    name: domain,
                    q_type: q_type,
                    class: class,
                    ttl: ttl,
                    len: len,
                    addr: addr,
                })
            }
            QueryType::SOA => {
                let mut mname = String::new();
                buf.read_qname(&mut mname)?;
                let mut rname = String::new();
                buf.read_qname(&mut rname)?;
                let serial = buf.read_u32()?;
                let refresh = buf.read_u32()?;
                let retry = buf.read_u32()?;
                let expire = buf.read_u32()?;
                let minimum = buf.read_u32()?;

                Ok(DNSRecord::SOA {
                    name: domain,
                    q_type: q_type,
                    class: class,
                    ttl: ttl,
                    len: len,
                    mname,
                    rname,
                    serial,
                    refresh,
                    retry,
                    expire,
                    minimum,
                })
            }
            QueryType::UNKNOWN(_) => {
                buf.step(len as usize)?; // Skip the data length of this particular record type
                Ok(DNSRecord::UNKNOWN {
                    name: domain,
                    q_type: q_type,
                    class: class,
                    ttl: ttl,
                    len: len,
                })
            }
        }
    }

    pub fn write<T: PacketBufferTrait>(&self, buf: &mut T) -> Result<()> {
        match *self {
            DNSRecord::A {
                ref name,
                q_type,
                class,
                ttl,
                len,
                ref addr,
            } => {
                buf.write_qname(&name)?;
                buf.write_u16(q_type.to_num())?;
                buf.write_u16(class)?;
                buf.write_u32(ttl)?;
                buf.write_u16(len)?;
                for octet in addr.octets().iter() {
                    buf.write(*octet)?;
                }
            }
            DNSRecord::NS {
                ref name,
                q_type,
                class,
                ttl,
                len,
                ref host,
            } => {
                buf.write_qname(&name)?;
                buf.write_u16(q_type.to_num())?;
                buf.write_u16(class)?;
                buf.write_u32(ttl)?;
                buf.write_u16(len)?;
                buf.write_qname(host)?;
            }
            DNSRecord::CNAME {
                ref name,
                q_type,
                class,
                ttl,
                len,
                ref host,
            } => {
                buf.write_qname(&name)?;
                buf.write_u16(q_type.to_num())?;
                buf.write_u16(class)?;
                buf.write_u32(ttl)?;
                buf.write_u16(len)?;
                buf.write_qname(host)?;
            }
            DNSRecord::MX {
                ref name,
                q_type,
                class,
                ttl,
                len,
                priority,
                ref host,
            } => {
                buf.write_qname(&name)?;
                buf.write_u16(q_type.to_num())?;
                buf.write_u16(class)?;
                buf.write_u32(ttl)?;
                buf.write_u16(len)?;
                buf.write_u16(priority)?;
                buf.write_qname(host)?;
            }
            DNSRecord::AAAA {
                ref name,
                q_type,
                class,
                ttl,
                len,
                ref addr,
            } => {
                buf.write_qname(&name)?;
                buf.write_u16(q_type.to_num())?;
                buf.write_u16(class)?;
                buf.write_u32(ttl)?;
                buf.write_u16(len)?;
                for segment in addr.segments().iter() {
                    buf.write_u16(*segment)?;
                }
            }
            DNSRecord::SOA {
                ref name,
                q_type,
                class,
                ttl,
                len,
                ref mname,
                ref rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                buf.write_qname(&name)?;
                buf.write_u16(q_type.to_num())?;
                buf.write_u16(class)?;
                buf.write_u32(ttl)?;
                buf.write_u16(len)?;
                buf.write_qname(&mname)?;
                buf.write_qname(&rname)?;
                buf.write_u32(serial)?;
                buf.write_u32(refresh)?;
                buf.write_u32(retry)?;
                buf.write_u32(expire)?;
                buf.write_u32(minimum)?;
            }
            DNSRecord::UNKNOWN { .. } => {
                println!("SKipping unknown record!");
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct DNSPacket {
    pub header: DNSHeader,
    pub questions: Vec<DNSQuestion>,
    pub answers: Vec<DNSRecord>,
    pub authority: Vec<DNSRecord>,
    pub addtional: Vec<DNSRecord>,
}

impl DNSPacket {
    pub fn new() -> DNSPacket {
        DNSPacket {
            header: DNSHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authority: Vec::new(),
            addtional: Vec::new(),
        }
    }
    pub fn from_buffer<T: PacketBufferTrait>(buf: &mut T) -> Result<DNSPacket> {
        let mut result = DNSPacket::new();
        result.header.read(buf)?;
        for _ in 0..result.header.q_count {
            let question = DNSQuestion::read(buf)?;
            result.questions.push(question);
        }

        for _ in 0..result.header.an_count {
            let record = DNSRecord::read(buf)?;
            result.answers.push(record);
        }

        for _ in 0..result.header.ns_count {
            result.authority.push(DNSRecord::read(buf)?);
        }

        for _ in 0..result.header.ad_count {
            result.addtional.push(DNSRecord::read(buf)?);
        }
        Ok(result)
    }

    pub fn add_question(&mut self, question: DNSQuestion) {
        self.questions.push(question);
        self.header.q_count += 1;
    }

    pub fn write<T: PacketBufferTrait>(&mut self, buf: &mut T) -> Result<()> {
        self.header.q_count = self.questions.len() as u16;
        self.header.an_count = self.answers.len() as u16;
        self.header.ns_count = self.authority.len() as u16;
        self.header.ad_count = self.addtional.len() as u16;
        self.header.write(buf)?;
        for question in &self.questions {
            question.write(buf)?;
        }
        for answer in &self.answers {
            answer.write(buf)?;
        }
        for auth in &self.authority {
            auth.write(buf)?;
        }
        for record in &self.addtional {
            record.write(buf)?;
        }
        Ok(())
    }

    pub fn get_random_a(&self) -> Option<Ipv4Addr> {
        self.answers
            .iter()
            .filter_map(|record| match record {
                DNSRecord::A { addr, .. } => Some(*addr),
                _ => None,
            })
            .next()
    }

    pub fn get_ns<'a>(&'a self, qname: &'a str) -> impl Iterator<Item = (&'a str, &'a str)> {
        self.authority
            .iter()
            .filter_map(|record| match record {
                DNSRecord::NS { name, host, .. } => Some((name.as_str(), host.as_str())),
                _ => None,
            })
            .filter(move |(name, _)| qname.ends_with(*name))
    }

    pub fn get_resolved_ns(&self, qname: &str) -> Option<Ipv4Addr> {
        self.get_ns(qname)
            .flat_map(|(_, host)| {
                self.addtional
                    .iter()
                    .filter_map(move |record| match record {
                        DNSRecord::A { name, addr, .. } if name == host => Some(addr),
                        _ => None,
                    })
            })
            .map(|addr| *addr)
            .next()
    }

    pub fn get_unresolved_ns<'a>(&'a self, qname: &'a str) -> Option<&'a str> {
        self.get_ns(qname).map(|(_, host)| host).next()
    }
}

impl From<Vec<DNSRecord>> for DNSPacket {
    fn from(records: Vec<DNSRecord>) -> Self {
        let mut packet = DNSPacket::new();
        packet.answers = records;
        packet
    }
}