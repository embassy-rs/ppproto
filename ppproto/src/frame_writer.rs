use super::crc::crc16;
use super::Error;

pub struct FrameWriter<'a> {
    buf: &'a mut [u8],
    len: usize,
    crc: u16,
    asyncmap: u32,
}

impl<'a> FrameWriter<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self {
            buf,
            len: 0,
            crc: 0,
            asyncmap: 0xFFFFFFFF,
        }
    }

    pub fn new_with_asyncmap(buf: &'a mut [u8], asyncmap: u32) -> Self {
        Self {
            buf,
            len: 0,
            crc: 0,
            asyncmap,
        }
    }

    pub fn get(self) -> &'a mut [u8] {
        &mut self.buf[..self.len]
    }

    pub fn start(&mut self) -> Result<(), Error> {
        self.crc = crc16(0xFFFF, &[0xFF, 0x03]);
        self.append_raw(&[0x7e, 0xff])?;
        self.append_escaped(&[0x03])?;

        Ok(())
    }

    pub fn finish(&mut self) -> Result<(), Error> {
        let crc = self.crc ^ 0xFFFF;
        self.append_escaped(&crc.to_le_bytes())?;
        self.append_raw(&[0x7e])?;

        Ok(())
    }

    fn append_raw(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.len + data.len() > self.buf.len() {
            Err(Error::NoMem)
        } else {
            self.buf[self.len..][..data.len()].copy_from_slice(data);
            self.len += data.len();
            Ok(())
        }
    }

    fn append_escaped(&mut self, data: &[u8]) -> Result<(), Error> {
        for &b in data {
            let escape = match b {
                0..=0x1f => self.asyncmap & (1 << (b as u32)) != 0,
                0x7d => true,
                0x7e => true,
                _ => false,
            };

            if escape {
                self.append_raw(&[0x7d, b ^ 0x20])?;
            } else {
                self.append_raw(&[b])?;
            }
        }
        Ok(())
    }

    pub fn append(&mut self, data: &[u8]) -> Result<(), Error> {
        self.append_escaped(data)?;
        self.crc = crc16(self.crc, data);
        Ok(())
    }
}
