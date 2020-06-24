use eyre::{eyre, Result};
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub trait PacketBufferTrait {
    fn read(&mut self) -> Result<u8>;
    fn get(&self, pos: usize) -> Result<u8>;
    fn get_range(&self, pos: usize, len: usize) -> Result<&[u8]>;
    fn set(&mut self, pos: usize, val: u8) -> Result<()>;
    fn pos(&self) -> usize;
    fn seek(&mut self, pos: usize) -> Result<()>;
    fn step(&mut self, steps: usize) -> Result<()>;
    fn write(&mut self, val: u8) -> Result<()>;

    fn read_u16(&mut self) -> Result<u16> {
        let res = ((self.read()? as u16) << 8) | (self.read()? as u16);
        Ok(res)
    }

    fn read_u32(&mut self) -> Result<u32> {
        let res = ((self.read_u16()? as u32) << 16 ) | (self.read_u16()? as u32);
        Ok(res)
    }

    fn write_u16(&mut self, val: u16) -> Result<()> {
        self.write((val >> 8) as u8)?;
        self.write((val & 0xFF) as u8)?;
        Ok(())
    }

    fn write_u32(&mut self, val: u32) -> Result<()> {
        self.write_u16((val >> 16) as u16)?;
        self.write_u16((val & 0xFFFF) as u16)?;
        Ok(())
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
                    self.seek(pos + 2)?;
                }

                let byte2 = self.get(pos+1)? as u16;
                let offset = ((len as u16) ^ 0xC0) << 8 | byte2;
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
            self.seek(pos)?;
        }
        Ok(())
    }

    fn write_qname(&mut self, qname: &str) -> Result<()> {
        for label in qname.split('.') {
            let len = label.len();
            if len > 63 {
                return Err(eyre!("Length exceeds 63 characters"));
            }
            self.write(len as u8)?;
            for byte in label.bytes() {
                self.write(byte)?;
            }
        }
        self.write(0)?; // Null length to signify end of name
        Ok(())
    }
}

#[derive(Clone)]
pub struct ArrayBuffer {
    pub buf: [u8; 512],
    pub pos: usize,
}

impl PacketBufferTrait for ArrayBuffer {
    fn pos(&self) -> usize {
        self.pos
    }

    fn step(&mut self, steps: usize) -> Result<()>{
        if self.pos + steps > 512 {
            return Err(eyre!("Buffer position exceeded, pos: {}", self.pos));
        }
        self.pos += steps;
        Ok(())
    }

    fn seek(&mut self, pos: usize) -> Result<()> {
        if pos > 512 {
            return Err(eyre!("Buffer position exceeded, pos: {}", pos));
        }
        self.pos = pos;
        Ok(())
    }

    fn read(&mut self) -> Result<u8> {
        if self.pos >= 512 {
            return Err(eyre!("Buffer position exceeded, pos: {}", self.pos));
        }
        let result = self.buf[self.pos];
        self.pos += 1;
        Ok(result)
    }

    fn get(&self, pos: usize) -> Result<u8> {
        if pos >= 512 {
            return Err(eyre!("GET: Buffer position exceeded, pos: {}", self.pos));
        }
        let res = self.buf[pos];
        Ok(res)
    }

    fn get_range(&self, pos: usize, len: usize) -> Result<&[u8]> {
        if pos >= 512 {
            return Err(eyre!("Buffer position exceeded, pos: {}", self.pos));
        }
        let res = &self.buf[pos..pos+len];
        Ok(res)
    }

    fn set(&mut self, pos: usize, val: u8) -> Result<()> {
        self.buf[pos] = val;
        Ok(())
    }

    fn write(&mut self, val: u8) -> Result<()> {
        if self.pos >= 512 {
            return Err(eyre!("Buffer Limit Exceeded!"));
        }
        self.buf[self.pos] = val;
        self.pos += 1;
        Ok(())
    }

}

impl ArrayBuffer {
    pub fn new() -> ArrayBuffer {
        return ArrayBuffer {
            buf: [0; 512],
            pos: 0,
        };
    }
}

pub struct VecBuffer {
    pub buf: Vec<u8>,
    pub pos: usize
}

impl PacketBufferTrait for VecBuffer {
    fn pos(&self) -> usize {
        self.pos
    }

    fn step(&mut self, steps: usize) -> Result<()> {
        if self.pos + steps > self.buf.len() {
            return Err(eyre!("Buffer position exceeded, pos: {}", self.pos));
        }
        self.pos += steps;
        Ok(())
    }

    fn seek(&mut self, pos: usize) -> Result<()> {
        if pos > self.buf.len() {
            return Err(eyre!("Buffer position exceeded, pos: {}", pos));
        }
        self.pos = pos;
        Ok(())
    }

    fn read(&mut self) -> Result<u8> {
        if self.pos >= self.buf.len() {
            return Err(eyre!("Buffer position exceeded, pos: {}", self.pos));
        }
        let result = self.buf[self.pos];
        self.pos += 1;
        Ok(result)
    }

    fn get(&self, pos: usize) -> Result<u8> {
        if pos >= self.buf.len() {
            return Err(eyre!("GET: Buffer position exceeded, pos: {}", self.pos));
        }
        let res = self.buf[pos];
        Ok(res)
    }

    fn get_range(&self, pos: usize, len: usize) -> Result<&[u8]> {
        if pos >= self.buf.len() {
            return Err(eyre!("Buffer position exceeded, pos: {}", self.pos));
        }
        let res = &self.buf[pos..pos+len];
        Ok(res)
    }

    fn set(&mut self, pos: usize, val: u8) -> Result<()> {
        self.buf[pos] = val;
        Ok(())
    }

    fn write(&mut self, val: u8) -> Result<()> {
        self.buf.push(val);
        self.pos += 1;
        Ok(())
    }
}

impl VecBuffer {
    pub fn new() -> VecBuffer {
        VecBuffer {
            buf: Vec::new(),
            pos: 0,
        }
    }

    pub async fn from_socket(socket: &mut TcpStream) -> Result<VecBuffer> {
        let size = socket.read_u16().await?;
        let mut new_socket = socket.take(size as u64);
        let mut res_vec = Vec::with_capacity(size as usize);
        new_socket.read_to_end(&mut res_vec).await?;
        Ok(VecBuffer {
            buf: res_vec,
            pos: 0,
        })
    }

    pub async fn to_socket(&mut self, socket: &mut TcpStream) -> Result<()> {
        let size = self.buf.len();
        socket.write_u16(size as u16).await?;
        socket.write(&self.buf).await?;
        Ok(())
    }
}