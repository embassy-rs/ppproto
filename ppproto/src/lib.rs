#![cfg_attr(not(feature = "std"), no_std)]

mod crc;
mod frame_reader;
mod frame_writer;
mod ipv4cp;
mod lcp;
mod options;
mod packet_writer;
mod pap;

use as_slice::AsMutSlice;
use core::convert::TryInto;
use core::marker::PhantomData;
use core::ops::Range;
use defmt::{panic, *};
use num_enum::{FromPrimitive, IntoPrimitive};

use self::frame_reader::FrameReader;
use self::frame_writer::FrameWriter;
use self::ipv4cp::IPv4CP;
use self::lcp::{AuthType, LCP};
use self::options::{State, StateMachine};
use self::pap::{State as PAPState, PAP};

pub use ipv4cp::Ipv4Status;

#[derive(Debug, Copy, Clone, Eq, PartialEq, defmt::Format)]
pub enum Error {
    TooShort,
    Invalid,
    Unsupported,
    NoMem,
    InvalidState,
}

#[derive(FromPrimitive, IntoPrimitive, Copy, Clone, Eq, PartialEq, Debug, defmt::Format)]
#[repr(u16)]
pub(crate) enum ProtocolType {
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

#[derive(
    FromPrimitive, IntoPrimitive, Copy, Clone, Eq, PartialEq, Debug, Ord, PartialOrd, defmt::Format,
)]
#[repr(u8)]
pub(crate) enum Code {
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

#[derive(Copy, Clone, Eq, PartialEq, Debug, Ord, PartialOrd, defmt::Format)]
enum Phase {
    Dead,
    Establish,
    Auth,
    Network,
    Open,
}

pub enum Action<B> {
    None,
    Received(B, Range<usize>),
    Transmit(usize),
}

pub struct Config<'a> {
    pub username: &'a [u8],
    pub password: &'a [u8],
}

pub struct PPP<'a, B: AsMutSlice<Element = u8>> {
    frame_reader: FrameReader,
    rx_buf: Option<B>,

    phase: Phase,
    lcp: StateMachine<LCP>,
    pap: PAP<'a>,
    ipv4cp: StateMachine<IPv4CP>,
}

#[derive(Debug, defmt::Format)]
pub struct Status {
    /// IPv4 configuration obtained from IPv4CP. None if IPv4CP is not up.
    pub ipv4: Option<Ipv4Status>,
}

impl<'a, B: AsMutSlice<Element = u8>> PPP<'a, B> {
    pub fn new(config: Config<'a>) -> Self {
        Self {
            frame_reader: FrameReader::new(),
            rx_buf: None,

            phase: Phase::Dead,
            lcp: StateMachine::new(LCP::new()),
            pap: PAP::new(config.username, config.password),
            ipv4cp: StateMachine::new(IPv4CP::new()),
        }
    }

    pub fn has_rx_buf(&self) -> bool {
        self.rx_buf.is_some()
    }

    pub fn put_rx_buf(&mut self, rx_buf: B) {
        if self.rx_buf.is_some() {
            panic!("called put_rx_buf when we already have a buffer.")
        }

        self.rx_buf = Some(rx_buf)
    }

    pub fn status(&self) -> Status {
        Status {
            ipv4: if self.ipv4cp.state() == State::Opened {
                Some(self.ipv4cp.proto().status())
            } else {
                None
            },
        }
    }

    pub fn open(&mut self) -> Result<(), Error> {
        match self.phase {
            Phase::Dead => {
                self.phase = Phase::Establish;
                Ok(())
            }
            _ => Err(Error::InvalidState),
        }
    }

    /// Process received data and generate data to be send.
    ///
    /// Action::Received is returned when an IP packet is received. You must then pass the packet
    /// to higher layers for processing.
    ///
    /// You must provide buffer space for data to be transmitted, and transmit the returned slice
    /// over the serial connection if Action::Transmit is returned.
    pub fn poll(&mut self, tx_buf: &mut [u8]) -> Result<Action<B>, Error> {
        let mut ww = FrameWriter::new(tx_buf);
        let w = &mut ww;

        let buf = unwrap!(self.rx_buf.as_mut(), "called poll() without an rx_buf").as_mut_slice();

        // Handle input
        if let Some(range) = self.frame_reader.receive() {
            let pkt = &mut buf[range.clone()];
            let proto = u16::from_be_bytes(pkt[0..2].try_into().unwrap());

            match proto.into() {
                ProtocolType::LCP => self.lcp.handle(pkt, w)?,
                ProtocolType::PAP => self.pap.handle(pkt, w)?,
                ProtocolType::IPv4 => {
                    return Ok(Action::Received(
                        self.rx_buf.take().unwrap(),
                        (range.start + 2)..range.end,
                    ))
                }
                ProtocolType::IPv4CP => self.ipv4cp.handle(pkt, w)?,
                ProtocolType::Unknown => self.lcp.send_protocol_reject(pkt, w)?,
            }
        }

        // TODO this state machine can probably be written in nicer way.
        // TODO this is probably not rfc compliant, check what other impls do
        let old_phase = self.phase;
        match self.phase {
            Phase::Dead => {}
            Phase::Establish => {
                if self.lcp.state() == State::Closed {
                    self.lcp.open(w)?;
                }

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
            info!("PPP link phase {:?} -> {:?}", old_phase, self.phase);
        }

        let r = ww.len();
        if r == 0 {
            Ok(Action::None)
        } else {
            Ok(Action::Transmit(r))
        }
    }

    /// Send an IP packet.
    ///
    /// You must provide buffer space for the data to be transmitted, and transmit the returned
    /// slice over the serial connection.
    pub fn send(&mut self, pkt: &[u8], tx_buf: &mut [u8]) -> Result<usize, Error> {
        // TODO check IPv4CP is up

        let mut w = FrameWriter::new_with_asyncmap(tx_buf, self.lcp.proto().asyncmap_remote);
        let proto: u16 = ProtocolType::IPv4.into();
        w.start()?;
        w.append(&proto.to_be_bytes())?;
        w.append(pkt)?;
        w.finish()?;
        Ok(w.len())
    }

    /// Consume data received from the serial connection.
    ///
    /// After calling `consume`, `poll` must be called to process the consumed data.
    ///
    /// Returns how many bytes were actually consumed. If less than `data.len()`, `consume`
    /// must be called again with the remaining data.
    pub fn consume(&mut self, data: &[u8]) -> usize {
        let buf = unwrap!(self.rx_buf.as_mut(), "called consume() without an rx_buf");
        self.frame_reader.consume(buf.as_mut_slice(), data)
    }
}
