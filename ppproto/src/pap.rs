use core::convert::TryInto;
use defmt::{assert, *};

use super::frame_writer::FrameWriter;
use super::packet_writer::PacketWriter;
use super::{Code, Error, ProtocolType};

#[derive(Debug, Copy, Clone, Eq, PartialEq, defmt::Format)]
pub enum State {
    Closed,
    ReqSent,
    Opened,
}
pub struct PAP<'a> {
    state: State,
    id: u8,

    username: &'a [u8],
    password: &'a [u8],
}

impl<'a> PAP<'a> {
    pub fn new(username: &'a [u8], password: &'a [u8]) -> Self {
        assert!(username.len() <= u8::MAX as usize);
        assert!(password.len() <= u8::MAX as usize);
        Self {
            state: State::Closed,
            id: 1,
            username,
            password,
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn open(&mut self, w: &mut FrameWriter<'_>) -> Result<(), Error> {
        match self.state {
            State::Closed => {
                self.send_configure_request(w)?;
                self.state = State::ReqSent;
            }
            _ => {}
        }
        Ok(())
    }

    pub fn close(&mut self, _w: &mut FrameWriter<'_>) -> Result<(), Error> {
        self.state = State::Closed;
        Ok(())
    }

    pub fn handle(&mut self, pkt: &mut [u8], w: &mut FrameWriter<'_>) -> Result<(), Error> {
        if pkt.len() < 6 {
            info!("warn: too short");
            return Err(Error::TooShort);
        }
        let code = Code::from(pkt[2]);
        let _id = pkt[3];
        let len = u16::from_be_bytes(pkt[4..6].try_into().unwrap()) as usize;
        if len > pkt.len() {
            info!("warn: len too short");
            return Err(Error::TooShort);
        }
        let _pkt = &mut pkt[..len + 2];

        info!("PAP: rx {:?}", code);
        let old_state = self.state;
        match (code, self.state) {
            (Code::ConfigureAck, State::ReqSent) => self.state = State::Opened,
            (Code::ConfigureNack, State::ReqSent) => self.send_configure_request(w)?,
            _ => {}
        }

        if old_state != self.state {
            info!("PAP: state {:?} -> {:?}", old_state, self.state);
        }

        Ok(())
    }

    fn next_id(&mut self) -> u8 {
        self.id = self.id.wrapping_add(1);
        self.id
    }

    fn send_configure_request(&mut self, w: &mut FrameWriter<'_>) -> Result<(), Error> {
        info!("PAP: tx {:?}", Code::ConfigureReq);

        let mut p = PacketWriter::new();
        p.append(&[self.username.len() as u8])?;
        p.append(self.username)?;
        p.append(&[self.password.len() as u8])?;
        p.append(self.password)?;

        p.write(w, ProtocolType::PAP, Code::ConfigureReq, self.next_id())
    }
}
