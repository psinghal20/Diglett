use eyre::{eyre, Result};

#[derive(Clone)]
struct PacketBuffer {
    buf: [u8; 512],
    pos: usize,
}

impl PacketBuffer {
    fn new() -> PacketBuffer {
        return PacketBuffer {
            buf: [0; 512],
            pos: 0,
        };
    }

    fn pos(&self) -> usize {
        self.pos
    }

    fn step(&mut self) {
        self.pos += 1;
    }

    fn seek(&mut self, pos: usize) {
        self.pos = pos;
    }

    fn read(&mut self) -> Result<u8> {
        if self.pos >= 512 {
            return Err(eyre!("Buffer position exceeded"));
        }
        let result = self.buf[self.pos];
        self.step();
        Ok(result)
    }

    fn get(&self, pos: usize) -> Result<u8> {
        if pos >= 512 {
            return Err(eyre!("Buffer position exceeded"));
        }
        let res = self.buf[pos];
        Ok(res)
    }

    fn get_range(&self, pos: usize, len: usize) -> Result<&[u8]> {
        if pos >= 512 {
            return Err(eyre!("Buffer position exeeded!"));
        }
        let res = &self.buf[pos..pos+len];
        Ok(res)
    }

    fn read_u16(&mut self) -> Result<u16> {
        let res = ((self.read()? as u16) << 8) | (self.read()? as u16);
        Ok(res)
    }

    fn read_u32(&mut self) -> Result<u32> {
        let res = ((self.read_u16()? as u32) << 16 ) | (self.read_u16()? as u32);
        Ok(res)
    }

    fn read_qname(&mut self, output: &mut String) -> Result<()> {
        let mut pos = self.pos();
        let mut jump = false;
        let mut delim = "";
        loop {
            let len = self.get(pos)?;
            if(len & 0xC0) == 0xC0 {
                // The first two bits are 1 so we need to jump
                if !jump {
                    self.seek(pos + 2);
                }

                let byte2 = self.get(pos+1)? as u16;
                let offset = (len as u16 ^ 0xC0) << 8 | byte2;
                pos = offset as usize;
                jump = true;
            } else {
                pos += 1; // move to next byte
                if len == 0 {
                    break;
                    // Null length means end of label
                }
                output.push_str(delim);

                let str_buf = self.get_range(pos, len as usize)?;
                output.push_str(&String::from_utf8_lossy(str_buf).to_lowercase());

                delim = "."; //After initial null delimiter use, we add period as delimiter
                pos += len as usize;
            }
        }

        if !jump {
            self.seek(pos);
        }
        Ok(())
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RCode {
    NOERROR,
    FORMERR,
    SERVFAIL,
    NXDOMAIN,
    NOTIMP,
    REFUSED
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

struct DNSHeader {
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
    fn new() -> DNSHeader {
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
            ad_count: 0
        }
    }

    pub fn read(&mut self, mut buf: PacketBuffer) -> Result<()> {
        self.id = buf.read_u16()?;
        let flags = buf.read_u16()?;
        self.query_response = (flags & (1 << 15)) > 0;
        self.opcode = (flags >> 11) as u8 & 0xF;
        self.auth_answer = (flags & (1<<10)) > 0;
        self.truncated_msg = (flags & (1<<9)) > 0;
        self.recur_desired = (flags & (1<<8)) > 0;
        self.recur_available = (flags & (1<<7)) > 0;
        self.z_res = (flags & (7<<4)) > 0;
        self.res_code = RCode::from_num((flags & 0xF) as usize);
        self.q_count = buf.read_u16()?;
        self.an_count = buf.read_u16()?;
        self.ns_count = buf.read_u16()?;
        self.ad_count = buf.read_u16()?;
        Ok(())
    }
}

#[derive(PartialEq,Eq,Debug,Clone,Hash,Copy)]
pub enum QueryType {
    UNKNOWN(u16),
    A,
}

impl QueryType {
    fn to_num(&self) -> u16 {
        match *self {
            Self::UNKNOWN(code) => code,
            Self::A => 1,
        }
    }
    fn from_num(&self, num: u16) -> Self {
        match num {
            1 => Self::A,
            _ => Self::UNKNOWN(num)
        }
    }
}