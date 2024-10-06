use core::net::Ipv4Addr;

use num_enum::{FromPrimitive, IntoPrimitive};

use super::option_fsm::{Protocol, Verdict};
use crate::wire::ProtocolType;

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
    address: Ipv4Addr,
    is_rejected: bool,
}

impl IpOption {
    fn new() -> Self {
        Self {
            address: Ipv4Addr::UNSPECIFIED,
            is_rejected: false,
        }
    }

    fn get(&self) -> Option<Ipv4Addr> {
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
            match <[u8; 4]>::try_from(data) {
                // Peer addr is OK
                Ok(data) => self.address = Ipv4Addr::from(data),
                // Peer wants us to use an address that's not 4 bytes.
                // Should never happen, but mark option as rejected just in case to
                // avoid endless loop.
                Err(_) => self.is_rejected = true,
            }
        }
    }
}

/// Status of the IPv4 connection.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Ipv4Status {
    /// Our adress
    pub address: Option<Ipv4Addr>,
    /// The peer's address
    pub peer_address: Option<Ipv4Addr>,
    /// DNS servers provided by the peer.
    pub dns_servers: [Option<Ipv4Addr>; 2],
}

pub(crate) struct IPv4CP {
    peer_address: Ipv4Addr,

    address: IpOption,
    dns_server_1: IpOption,
    dns_server_2: IpOption,
}

impl IPv4CP {
    pub fn new() -> Self {
        Self {
            peer_address: Ipv4Addr::UNSPECIFIED,

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
            OptionCode::IpAddress => match <[u8; 4]>::try_from(data) {
                Ok(data) => {
                    self.peer_address = Ipv4Addr::from(data);
                    Verdict::Ack
                }
                Err(_) => Verdict::Rej,
            },
            _ => Verdict::Rej,
        }
    }

    fn own_options(&mut self, mut f: impl FnMut(u8, &[u8])) {
        if !self.address.is_rejected {
            f(OptionCode::IpAddress.into(), &self.address.address.octets());
        }
        if !self.dns_server_1.is_rejected {
            f(OptionCode::Dns1.into(), &self.dns_server_1.address.octets());
        }
        if !self.dns_server_2.is_rejected {
            f(OptionCode::Dns2.into(), &self.dns_server_2.address.octets());
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
