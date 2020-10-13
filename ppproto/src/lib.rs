#![cfg_attr(not(feature = "std"), no_std)]

mod crc;
mod frame_reader;
mod frame_writer;
mod ipv4cp;
mod lcp;
mod options;
mod packet_writer;
mod pap;

use core::convert::TryInto;
use core::marker::PhantomData;
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
    InvalidState,
}

#[derive(FromPrimitive, IntoPrimitive, Copy, Clone, Eq, PartialEq, Debug)]
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

#[derive(FromPrimitive, IntoPrimitive, Copy, Clone, Eq, PartialEq, Debug, Ord, PartialOrd)]
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

#[derive(Copy, Clone, Eq, PartialEq, Debug, Ord, PartialOrd)]
enum Phase {
    Dead,
    Establish,
    Auth,
    Network,
    Open,
}

pub enum Action<'a, 'b> {
    None,
    Received(&'a mut [u8], Sender<'a>),
    Transmit(&'b mut [u8]),
}

pub struct PPP<'a> {
    frame_reader: FrameReader<'a>,
    phase: Phase,
    lcp: StateMachine<LCP>,
    pap: PAP,
    ipv4cp: StateMachine<IPv4CP>,
}

impl<'a> PPP<'a> {
    pub fn new(rx_buf: &'a mut [u8]) -> Self {
        Self {
            frame_reader: FrameReader::new(rx_buf),
            phase: Phase::Dead,
            lcp: StateMachine::new(LCP::new()),
            pap: PAP::new(b"orange", b"orange"),
            ipv4cp: StateMachine::new(IPv4CP::new()),
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
    /// to higher layers for processing. A Sender is also returned to allow sending outgoing
    /// packets while keeping the borrow of the incoming packet.
    ///
    /// You must provide buffer space for data to be transmitted, and transmit the returned slice
    /// over the serial connection if Action::Transmit is returned.
    pub fn poll<'b, 'c>(&'b mut self, tx_buf: &'c mut [u8]) -> Result<Action<'b, 'c>, Error> {
        let mut ww = FrameWriter::new(tx_buf);
        let w = &mut ww;

        // Handle input
        if let Some(pkt) = self.frame_reader.receive() {
            let proto = u16::from_be_bytes(pkt[0..2].try_into().unwrap());

            match proto.into() {
                ProtocolType::LCP => self.lcp.handle(pkt, w)?,
                ProtocolType::PAP => self.pap.handle(pkt, w)?,
                ProtocolType::IPv4 => {
                    return Ok(Action::Received(
                        &mut pkt[2..],
                        Sender {
                            phantom: PhantomData,
                        },
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
            log::info!("PPP link phase {:?} -> {:?}", old_phase, self.phase);
        }

        let r = ww.get();
        if r.len() == 0 {
            Ok(Action::None)
        } else {
            Ok(Action::Transmit(r))
        }
    }

    /// Get a Sender object.
    pub fn sender(&mut self) -> Sender<'_> {
        Sender {
            phantom: PhantomData,
        }
    }

    /// Consume data received from the serial connection.
    ///
    /// After calling `consume`, `poll` must be called to process the consumed data.
    ///
    /// Returns how many bytes were actually consumed. If less than `data.len()`, `consume`
    /// must be called again with the remaining data.
    pub fn consume(&mut self, data: &[u8]) -> usize {
        self.frame_reader.consume(data)
    }
}

/// Sender can be used to send IP packets over a PPP connection.
pub struct Sender<'a> {
    phantom: PhantomData<&'a mut ()>,
}

impl<'a> Sender<'a> {
    /// Send an IP packet.
    ///
    /// You must provide buffer space for the data to be transmitted, and transmit the returned
    /// slice over the serial connection.
    pub fn send<'b>(&mut self, pkt: &[u8], tx_buf: &'b mut [u8]) -> Result<&'b mut [u8], Error> {
        // TODO check IPv4CP is up

        let mut w = FrameWriter::new(tx_buf);
        let proto: u16 = ProtocolType::IPv4.into();
        w.start()?;
        w.append(&proto.to_be_bytes())?;
        w.append(pkt)?;
        w.finish()?;
        Ok(w.get())
    }
}
