use core::convert::TryInto;

use crate::wire::{Code, PPPPayload, Packet, Payload, ProtocolType};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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

    pub fn open(&mut self) -> Packet<'_> {
        assert!(self.state == State::Closed);
        self.state = State::ReqSent;
        self.send_configure_request()
    }

    pub fn close(&mut self) {
        self.state = State::Closed;
    }

    pub fn handle(&mut self, pkt: &mut [u8], mut tx: impl FnMut(Packet<'_>)) {
        if pkt.len() < 6 {
            info!("warn: too short");
            return;
        }
        let code = Code::from(pkt[2]);
        let _id = pkt[3];
        let len = u16::from_be_bytes(pkt[4..6].try_into().unwrap()) as usize;
        if len > pkt.len() {
            info!("warn: len too short");
            return;
        }
        let _pkt = &mut pkt[..len + 2];

        info!("PAP: rx {:?}", code);
        let old_state = self.state;
        match (code, self.state) {
            (Code::ConfigureAck, State::ReqSent) => self.state = State::Opened,
            (Code::ConfigureNack, State::ReqSent) => tx(self.send_configure_request()),
            _ => {}
        }

        if old_state != self.state {
            info!("PAP: state {:?} -> {:?}", old_state, self.state);
        }
    }

    fn next_id(&mut self) -> u8 {
        self.id = self.id.wrapping_add(1);
        self.id
    }

    fn send_configure_request(&mut self) -> Packet<'a> {
        info!("PAP: tx {:?}", Code::ConfigureReq);
        Packet {
            proto: ProtocolType::PAP,
            payload: Payload::PPP(
                Code::ConfigureReq,
                self.next_id(),
                PPPPayload::PAP(self.username, self.password),
            ),
        }
    }
}
