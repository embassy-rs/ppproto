use super::crc::crc16;
use super::Error;

pub struct FrameWriter<'a> {
    buf: &'a mut [u8],
    len: usize,
    crc: u16,
}

impl<'a> FrameWriter<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self {
            buf,
            len: 0,
            crc: 0,
        }
    }

    pub fn get(self) -> &'a mut [u8] {
        &mut self.buf[..self.len]
    }

    pub fn start(&mut self) -> Result<(), Error> {
        self.crc = crc16(0xFFFF, &[0xFF, 0x03]);
        self.append_raw(&[0x7e, 0xff, 0x7d, 0x23])?;

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
            match b {
                0..=0x1f | 0x7d | 0x7e => self.append_raw(&[0x7d, b ^ 0x20])?,
                _ => self.append_raw(&[b])?,
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
