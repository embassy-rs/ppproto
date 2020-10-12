#![feature(with_options)]

mod crc;
mod frame_reader;
mod frame_writer;
mod ipv4cp;
mod lcp;
mod options;
mod packet_writer;
mod pap;

use core::convert::TryInto;
use managed::ManagedSlice;
use num_enum::{FromPrimitive, IntoPrimitive};

use self::frame_reader::FrameReader;
use self::frame_writer::FrameWriter;
use self::ipv4cp::IPv4CP;
use self::lcp::{AuthType, LCP};
use self::options::{State, StateMachine};
use self::pap::{State as PAPState, PAP};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
    TooShort,
    Invalid,
    Unsupported,
    NoMem,
}

#[derive(FromPrimitive, IntoPrimitive, Copy, Clone, Eq, PartialEq, Debug)]
#[repr(u16)]
pub enum ProtocolType {
    #[num_enum(default)]
    Unknown = 0,
    /// Link Control Protocol,  rfc1661
    LCP = 0xc021,
    /// Password Authentication Protocol, rfc1334
    PAP = 0xc023,
    /// Internet Protocol v4
    IPv4 = 0x0021,
    /// Internet Protocol v4 Control Protocol, rfc1332
    IPv4CP = 0x8021,
}

#[derive(FromPrimitive, IntoPrimitive, Copy, Clone, Eq, PartialEq, Debug, Ord, PartialOrd)]
#[repr(u8)]
pub enum Code {
    #[num_enum(default)]
    Unknown = 0,
    ConfigureReq = 1,
    ConfigureAck = 2,
    ConfigureNack = 3,
    ConfigureRej = 4,
    TerminateReq = 5,
    TerminateAck = 6,
    CodeRej = 7,
    ProtocolRej = 8,
    EchoReq = 9,
    EchoReply = 10,
    DiscardReq = 11,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Ord, PartialOrd)]
enum Phase {
    Establish,
    Auth,
    Network,
    Open,
}

pub enum Action<'a> {
    None,
    Response(&'a mut [u8]),
    Received(&'a mut [u8]),
}

pub struct PPP<'a> {
    tx_buf: ManagedSlice<'a, u8>,
    frame_reader: FrameReader<'a>,

    inner: Inner,
}

struct Inner {
    phase: Phase,
    lcp: StateMachine<LCP>,
    pap: PAP,
    ipv4cp: StateMachine<IPv4CP>,
}

impl<'a> PPP<'a> {
    pub fn new(rx_buf: ManagedSlice<'a, u8>, tx_buf: ManagedSlice<'a, u8>) -> Self {
        Self {
            tx_buf,
            frame_reader: FrameReader::new(rx_buf),
            inner: Inner {
                phase: Phase::Establish,
                lcp: StateMachine::new(LCP::new()),
                pap: PAP::new(b"orange", b"orange"),
                ipv4cp: StateMachine::new(IPv4CP::new()),
            },
        }
    }

    pub fn poll(&mut self) -> Action<'_> {
        let mut ww = FrameWriter::new(&mut self.tx_buf);
        let w = &mut ww;

        self.inner.lcp.open(w).unwrap();

        let r = ww.get();
        if r.len() == 0 {
            Action::None
        } else {
            Action::Response(r)
        }
    }

    pub fn send(&mut self, pkt: &[u8]) -> Result<&mut [u8], Error> {
        // TODO check IPv4CP is up

        let mut w = FrameWriter::new(&mut self.tx_buf);
        let proto: u16 = ProtocolType::IPv4.into();
        w.start()?;
        w.append(&proto.to_be_bytes())?;
        w.append(pkt)?;
        w.finish()?;
        Ok(w.get())
    }

    pub fn consume(&mut self, data: &[u8]) -> (usize, Action<'_>) {
        let (n, data) = self.frame_reader.consume(data);
        let pkt = match data {
            Some(pkt) => pkt,
            None => return (n, Action::None),
        };

        let r = self
            .inner
            .handle(pkt, &mut self.tx_buf)
            .unwrap_or_else(|e| {
                println!("Error handling packet: {:?}", e);
                Action::None
            });

        (n, r)
    }
}

impl Inner {
    fn handle<'a>(&mut self, pkt: &'a mut [u8], tx_buf: &'a mut [u8]) -> Result<Action<'a>, Error> {
        let mut ww = FrameWriter::new(tx_buf);
        let w = &mut ww;

        let proto = u16::from_be_bytes(pkt[0..2].try_into().unwrap());

        match proto.into() {
            ProtocolType::LCP => self.lcp.handle(pkt, w)?,
            ProtocolType::PAP => self.pap.handle(pkt, w)?,
            ProtocolType::IPv4 => return Ok(Action::Received(&mut pkt[2..])),
            ProtocolType::IPv4CP => self.ipv4cp.handle(pkt, w)?,
            ProtocolType::Unknown => self.lcp.send_protocol_reject(pkt, w)?,
        }

        let old_phase = self.phase;

        if self.lcp.state() != State::Opened {
            self.phase = Phase::Establish;
        }

        match self.phase {
            Phase::Establish => {
                if self.lcp.state() == State::Opened {
                    match self.lcp.proto().auth {
                        AuthType::None => {
                            self.ipv4cp.open(w)?;
                            self.phase = Phase::Network;
                        }
                        AuthType::PAP => {
                            self.pap.open(w)?;
                            self.phase = Phase::Auth;
                        }
                    }
                } else {
                    if self.pap.state() != PAPState::Closed {
                        self.pap.close(w)?;
                    }
                    if self.ipv4cp.state() != State::Closed {
                        self.ipv4cp.close(w)?;
                    }
                }
            }
            Phase::Auth => {
                if self.pap.state() == PAPState::Opened {
                    self.ipv4cp.open(w)?;
                    self.phase = Phase::Network;
                } else {
                    if self.ipv4cp.state() != State::Closed {
                        self.ipv4cp.close(w)?;
                    }
                }
            }
            Phase::Network => {
                if self.ipv4cp.state() == State::Opened {
                    self.phase = Phase::Open;
                }
            }
            Phase::Open => {}
        }

        if old_phase != self.phase {
            println!("PPP link phase {:?} -> {:?}", old_phase, self.phase);
        }

        let r = ww.get();
        if r.len() == 0 {
            Ok(Action::None)
        } else {
            Ok(Action::Response(r))
        }
    }
}
