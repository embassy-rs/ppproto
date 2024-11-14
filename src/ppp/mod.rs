mod ipv4cp;
mod lcp;
mod option_fsm;
mod pap;

use self::ipv4cp::IPv4CP;
use self::lcp::{AuthType, LCP};
use self::option_fsm::{OptionFsm, State};
use self::pap::{State as PAPState, PAP};
use crate::wire::{Packet, ProtocolType};

pub use self::ipv4cp::Ipv4Status;

/// PPP configuration.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Config<'a> {
    /// Username for PAP.
    pub username: &'a [u8],
    /// Password for PAP.
    pub password: &'a [u8],
}

/// Phase of the PPP connection.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Ord, PartialOrd)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Phase {
    /// Dead, not connected.
    Dead,
    /// Establishing initial connection.
    Establish,
    /// Authenticating with e.g. PAP.
    Auth,
    /// Negotiating network parameters, with e.g. IPv4CP
    Network,
    /// Connection is open, all layers are setup.
    Open,
}

/// Status of the PPP connection.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Status {
    /// Phase
    pub phase: Phase,
    /// IPv4 configuration obtained from IPv4CP. None if IPv4CP is not up.
    pub ipv4: Option<Ipv4Status>,
}

pub(crate) struct PPP<'a> {
    phase: Phase,
    opening: bool,
    pub(crate) lcp: OptionFsm<LCP>,
    pub(crate) pap: PAP<'a>,
    pub(crate) ipv4cp: OptionFsm<IPv4CP>,
}

impl<'a> PPP<'a> {
    pub fn new(config: Config<'a>) -> Self {
        Self {
            phase: Phase::Dead,
            opening: false,
            lcp: OptionFsm::new(LCP::new()),
            pap: PAP::new(config.username, config.password),
            ipv4cp: OptionFsm::new(IPv4CP::new()),
        }
    }

    pub fn status(&self) -> Status {
        Status {
            phase: self.phase,
            ipv4: if self.ipv4cp.state() == State::Opened {
                Some(self.ipv4cp.proto().status())
            } else {
                None
            },
        }
    }

    pub fn open(&mut self) -> Result<(), crate::InvalidStateError> {
        match self.phase {
            Phase::Dead => {
                self.phase = Phase::Establish;
                self.opening = true;
                Ok(())
            }
            _ => Err(crate::InvalidStateError),
        }
    }

    pub fn received(&mut self, pkt: &mut [u8], mut tx: impl FnMut(Packet<'_>)) {
        let proto = u16::from_be_bytes(pkt[0..2].try_into().unwrap());

        match proto.into() {
            ProtocolType::LCP => self.lcp.handle(pkt, &mut tx),
            ProtocolType::PAP => self.pap.handle(pkt, &mut tx),
            ProtocolType::IPv4 => todo!(),
            ProtocolType::IPv4CP => self.ipv4cp.handle(pkt, &mut tx),
            ProtocolType::Unknown => tx(self.lcp.send_protocol_reject(pkt)),
        }
    }

    pub fn poll(&mut self, mut tx: impl FnMut(Packet<'_>)) {
        // TODO this state machine can probably be written in nicer way.
        // TODO this is probably not rfc compliant, check what other impls do
        let old_phase = self.phase;
        match self.phase {
            Phase::Dead => {}
            Phase::Establish => {
                if self.lcp.state() == State::Closed {
                    tx(self.lcp.open());
                    self.opening = false;
                }

                if self.lcp.state() == State::Opened {
                    match self.lcp.proto().auth {
                        AuthType::None => {
                            tx(self.ipv4cp.open());
                            self.phase = Phase::Network;
                        }
                        AuthType::PAP => {
                            tx(self.pap.open());
                            self.phase = Phase::Auth;
                        }
                    }
                } else {
                    if self.pap.state() != PAPState::Closed {
                        self.pap.close();
                    }
                    if self.ipv4cp.state() != State::Closed {
                        self.ipv4cp.close();
                    }
                }
            }
            Phase::Auth => {
                if self.pap.state() == PAPState::Opened {
                    self.phase = Phase::Network;
                    tx(self.ipv4cp.open());
                } else {
                    if self.ipv4cp.state() != State::Closed {
                        self.ipv4cp.close();
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

        if self.lcp.state() == State::Closed && !self.opening {
            self.phase = Phase::Dead
        }

        if old_phase != self.phase {
            info!("PPP link phase {:?} -> {:?}", old_phase, self.phase);
        }
    }
}
