use super::frame_writer::FrameWriter;
use super::{Code, Error, ProtocolType};

pub(crate) struct PacketWriter {
    buf: [u8; 256],
    len: usize,
}

impl PacketWriter {
    pub fn new() -> Self {
        Self {
            buf: [0; 256],
            len: 0,
        }
    }

    pub fn reset(&mut self) {
        self.len = 0;
    }

    pub fn append(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.len + data.len() > self.buf.len() {
            Err(Error::NoMem)
        } else {
            self.buf[self.len..self.len + data.len()].copy_from_slice(data);
            self.len += data.len();
            Ok(())
        }
    }

    pub fn append_option(&mut self, code: u8, data: &[u8]) -> Result<(), Error> {
        let len = data.len() + 2;
        assert!(len <= u8::MAX as usize);
        self.append(&[code, len as u8])?;
        self.append(data)?;
        Ok(())
    }

    pub fn get_buf(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    pub fn write(
        &mut self,
        w: &mut FrameWriter<'_>,
        proto: ProtocolType,
        code: Code,
        id: u8,
    ) -> Result<(), Error> {
        let proto: u16 = proto.into();
        let code: u8 = code.into();
        let len: u16 = (self.len + 4) as u16;

        w.start()?;
        w.append(&proto.to_be_bytes())?;
        w.append(&[code, id])?;
        w.append(&len.to_be_bytes())?;
        w.append(&self.buf[..self.len])?;
        w.finish()
    }
}
