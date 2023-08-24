use heapless::Vec;

use crate::wire::{Code, OptionVal, Options, PPPPayload, Packet, Payload, ProtocolType};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) enum Verdict<'a> {
    Ack,
    Nack(&'a [u8]),
    Rej,
}

pub(crate) trait Protocol {
    fn protocol(&self) -> ProtocolType;

    fn own_options(&mut self, f: impl FnMut(u8, &[u8]));
    fn own_option_nacked(&mut self, code: u8, data: &[u8], is_rej: bool);

    fn peer_options_start(&mut self);
    fn peer_option_received(&mut self, code: u8, data: &[u8]) -> Verdict;
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) enum State {
    Closed,
    ReqSent,
    AckReceived,
    AckSent,
    Opened,
}

pub(crate) struct OptionFsm<P> {
    id: u8,
    state: State,
    proto: P,
}

impl<P: Protocol> OptionFsm<P> {
    pub fn new(proto: P) -> Self {
        Self {
            id: 1,
            state: State::Closed,
            proto,
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn proto(&self) -> &P {
        &self.proto
    }

    pub fn _proto_mut(&mut self) -> &mut P {
        &mut self.proto
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
            warn!("PPP packet too short");
            return;
        }
        let code = Code::from(pkt[2]);
        let id = pkt[3];
        let len = u16::from_be_bytes(pkt[4..6].try_into().unwrap()) as usize;
        if len + 2 > pkt.len() {
            warn!("PPP packet len too short");
            return;
        }
        let pkt = &mut pkt[..len + 2];

        debug!("{:?}: rx {:?}", self.proto.protocol(), code);
        let old_state = self.state;
        match (code, self.state) {
            // reply EchoReq on state Opened, ignore in all other states (including Closed!)
            (Code::EchoReq, State::Opened) => tx(self.send_echo_response(pkt)),
            (Code::EchoReq, x) => {
                debug!("ignoring unexpected EchoReq in state {:?}", x)
            }

            // DiscardReqs are, well, discarded.
            (Code::DiscardReq, _) => {}

            // in state Closed, reply to any packet with TerminateAck (except to EchoReq!)
            (_, State::Closed) => tx(self.send_terminate_ack(id)),

            (Code::ConfigureReq, _) => {
                let resp = self.received_configure_req(pkt);
                let acked = matches!(resp.payload, Payload::PPP(Code::ConfigureAck, _, _));
                tx(resp);

                match (acked, self.state) {
                    (_, State::Closed) => unreachable!(),
                    (true, State::ReqSent) => self.state = State::AckSent,
                    (true, State::AckReceived) => self.state = State::Opened,
                    (true, State::AckSent) => self.state = State::AckSent,
                    (true, State::Opened) => {
                        tx(self.send_configure_request());
                        self.state = State::AckSent;
                    }
                    (false, State::AckSent) => self.state = State::ReqSent,
                    (false, State::Opened) => {
                        tx(self.send_configure_request());
                        self.state = State::ReqSent;
                    }
                    (false, _) => {}
                }
            }

            (Code::ConfigureAck, State::ReqSent) => self.state = State::AckReceived,
            (Code::ConfigureAck, State::AckSent) => self.state = State::Opened,
            (Code::ConfigureAck, State::AckReceived) | (Code::ConfigureAck, State::Opened) => {
                self.state = State::ReqSent;
                tx(self.send_configure_request())
            }

            (Code::ConfigureNack, _) | (Code::ConfigureRej, _) => {
                let is_rej = code == Code::ConfigureRej;

                if pkt.len() < 6 {
                    panic!("too short")
                }
                let pkt = &pkt[6..]; // skip header

                parse_options(pkt, |code, data| {
                    self.proto.own_option_nacked(code, data, is_rej)
                })
                .unwrap();

                match self.state {
                    State::Closed => unreachable!(),
                    State::AckSent => {}
                    _ => self.state = State::ReqSent,
                }
                tx(self.send_configure_request())
            }
            (Code::TerminateReq, State::Opened) => {
                self.state = State::Closed;
                tx(self.send_terminate_ack(id))
            }
            (Code::TerminateReq, State::ReqSent)
            | (Code::TerminateReq, State::AckReceived)
            | (Code::TerminateReq, State::AckSent) => {
                self.state = State::ReqSent;
                tx(self.send_terminate_ack(id))
            }

            x => debug!(
                "ignoring unexpected packet {:?} in state {:?}",
                x, self.state
            ),
        };

        if old_state != self.state {
            debug!(
                "{:?}: state {:?} -> {:?}",
                self.proto.protocol(),
                old_state,
                self.state
            );
        }
    }

    fn next_id(&mut self) -> u8 {
        self.id = self.id.wrapping_add(1);
        self.id
    }

    fn send_configure_request(&mut self) -> Packet<'static> {
        let mut opts = Vec::new();

        self.proto.own_options(|code, data| {
            if opts.push(OptionVal::new(code, data)).is_err() {
                panic!("tx ConfigureReq: too many options")
            }
        });

        Packet {
            proto: self.proto.protocol(),
            payload: Payload::PPP(
                Code::ConfigureReq,
                self.next_id(),
                PPPPayload::Options(Options(opts)),
            ),
        }
    }

    fn _send_terminate_request<'a>(&mut self, reason: &'a mut [u8]) -> Packet<'a> {
        Packet {
            proto: self.proto.protocol(),
            payload: Payload::PPP(Code::TerminateReq, self.next_id(), PPPPayload::Raw(reason)),
        }
    }

    fn send_terminate_ack(&mut self, id: u8) -> Packet<'static> {
        Packet {
            proto: self.proto.protocol(),
            payload: Payload::PPP(Code::TerminateAck, id, PPPPayload::Raw(&mut [])),
        }
    }

    fn _send_code_reject<'a>(&mut self, pkt: &'a mut [u8]) -> Packet<'a> {
        Packet {
            proto: self.proto.protocol(),
            payload: Payload::PPP(
                Code::CodeRej,
                self.next_id(),
                PPPPayload::Raw(&mut pkt[2..]),
            ),
        }
    }

    fn send_echo_response<'a>(&mut self, pkt: &'a mut [u8]) -> Packet<'a> {
        pkt[2] = Code::EchoReply as u8;
        Packet {
            proto: self.proto.protocol(),
            payload: Payload::Raw(&mut pkt[2..]),
        }
    }

    // TODO maybe this should be in PPP because it's only for LCP
    pub fn send_protocol_reject<'a>(&mut self, pkt: &'a mut [u8]) -> Packet<'a> {
        Packet {
            proto: self.proto.protocol(),
            payload: Payload::PPP(Code::ProtocolRej, self.next_id(), PPPPayload::Raw(pkt)),
        }
    }

    fn received_configure_req(&mut self, pkt: &[u8]) -> Packet<'static> {
        let id = pkt[3];
        let mut code = Code::ConfigureAck;

        if pkt.len() < 6 {
            panic!("too short");
        }
        let pkt = &pkt[6..]; // skip header

        let mut opts = Vec::new();

        self.proto.peer_options_start();
        parse_options(pkt, |ocode, odata| {
            let (ret_code, data) = match self.proto.peer_option_received(ocode, odata) {
                Verdict::Ack => (Code::ConfigureAck, odata),
                Verdict::Nack(data) => (Code::ConfigureNack, data),
                Verdict::Rej => (Code::ConfigureRej, odata),
            };

            if code < ret_code {
                code = ret_code;
                opts.clear();
            }

            if code == ret_code {
                if opts.push(OptionVal::new(ocode, data)).is_err() {
                    panic!("rx ConfigureReq: too many options")
                }
            }
        })
        .unwrap();

        Packet {
            proto: self.proto.protocol(),
            payload: Payload::PPP(code, id, PPPPayload::Options(Options(opts))),
        }
    }
}

fn parse_options(mut pkt: &[u8], mut f: impl FnMut(u8, &[u8])) -> Result<(), MalformedError> {
    while pkt.len() != 0 {
        if pkt.len() < 2 {
            return Err(MalformedError);
        }

        let code = pkt[0];
        let len = pkt[1] as usize;

        if pkt.len() < len {
            return Err(MalformedError);
        }
        if len < 2 {
            return Err(MalformedError);
        }

        let data = &pkt[2..len];
        f(code, data);
        pkt = &pkt[len..];
    }

    Ok(())
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct MalformedError;
