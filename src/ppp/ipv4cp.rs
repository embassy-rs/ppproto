use num_enum::{FromPrimitive, IntoPrimitive};

use super::option_fsm::{Protocol, Verdict};
use crate::wire::ProtocolType;

/// IPv4 address.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Ipv4Address(pub [u8; 4]);

impl Ipv4Address {
    /// The unspecified address `0.0.0.0`.
    pub const UNSPECIFIED: Self = Self([0; 4]);

    /// Return whether this address is the unspecified address `0.0.0.0`.
    pub fn is_unspecified(&self) -> bool {
        *self == Self::UNSPECIFIED
    }
}

#[derive(FromPrimitive, IntoPrimitive, Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
enum OptionCode {
    #[num_enum(default)]
    Unknown = 0,
    IpAddress = 3,
    Dns1 = 129,
    Dns2 = 131,
}

struct IpOption {
    address: Ipv4Address,
    is_rejected: bool,
}

impl IpOption {
    fn new() -> Self {
        Self {
            address: Ipv4Address::UNSPECIFIED,
            is_rejected: false,
        }
    }

    fn get(&self) -> Option<Ipv4Address> {
        if self.is_rejected || self.address.is_unspecified() {
            None
        } else {
            Some(self.address)
        }
    }

    fn nacked(&mut self, data: &[u8], is_rej: bool) {
        if is_rej {
            self.is_rejected = true
        } else {
            if data.len() == 4 {
                self.address = Ipv4Address(data.try_into().unwrap());
            } else {
                // Peer wants us to use an address that's not 4 bytes.
                // Should never happen, but mark option as rejected just in case to
                // avoid endless loop.
                self.is_rejected = true
            }
        }
    }
}

/// Status of the IPv4 connection.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Ipv4Status {
    /// Our adress
    pub address: Option<Ipv4Address>,
    /// The peer's address
    pub peer_address: Option<Ipv4Address>,
    /// DNS servers provided by the peer.
    pub dns_servers: [Option<Ipv4Address>; 2],
}

pub(crate) struct IPv4CP {
    peer_address: Ipv4Address,

    address: IpOption,
    dns_server_1: IpOption,
    dns_server_2: IpOption,
}

impl IPv4CP {
    pub fn new() -> Self {
        Self {
            peer_address: Ipv4Address::UNSPECIFIED,

            address: IpOption::new(),
            dns_server_1: IpOption::new(),
            dns_server_2: IpOption::new(),
        }
    }

    pub fn status(&self) -> Ipv4Status {
        let peer_address = if self.peer_address.is_unspecified() {
            None
        } else {
            Some(self.peer_address)
        };

        Ipv4Status {
            address: self.address.get(),
            peer_address,
            dns_servers: [self.dns_server_1.get(), self.dns_server_2.get()],
        }
    }
}

impl Protocol for IPv4CP {
    fn protocol(&self) -> ProtocolType {
        ProtocolType::IPv4CP
    }

    fn peer_options_start(&mut self) {}

    fn peer_option_received(&mut self, code: u8, data: &[u8]) -> Verdict {
        let opt = OptionCode::from(code);
        trace!("IPv4CP: rx option {:?} {:?} {:?}", code, opt, data);
        match opt {
            OptionCode::IpAddress => {
                if data.len() == 4 {
                    self.peer_address = Ipv4Address(data.try_into().unwrap());
                    Verdict::Ack
                } else {
                    Verdict::Rej
                }
            }
            _ => Verdict::Rej,
        }
    }

    fn own_options(&mut self, mut f: impl FnMut(u8, &[u8])) {
        if !self.address.is_rejected {
            f(OptionCode::IpAddress.into(), &self.address.address.0);
        }
        if !self.dns_server_1.is_rejected {
            f(OptionCode::Dns1.into(), &self.dns_server_1.address.0);
        }
        if !self.dns_server_2.is_rejected {
            f(OptionCode::Dns2.into(), &self.dns_server_2.address.0);
        }
    }

    fn own_option_nacked(&mut self, code: u8, data: &[u8], is_rej: bool) {
        let opt = OptionCode::from(code);
        trace!("IPv4CP nak {:?} {:?} {:?} {:?}", code, opt, data, is_rej);
        match opt {
            OptionCode::Unknown => {}
            OptionCode::IpAddress => self.address.nacked(data, is_rej),
            OptionCode::Dns1 => self.dns_server_1.nacked(data, is_rej),
            OptionCode::Dns2 => self.dns_server_2.nacked(data, is_rej),
        }
    }
}
