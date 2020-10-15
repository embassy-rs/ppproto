use num_enum::{FromPrimitive, IntoPrimitive};

use super::options::{Protocol, Verdict};
use super::packet_writer::PacketWriter;
use super::{Error, ProtocolType};

use smoltcp::wire::Ipv4Address;

#[derive(FromPrimitive, IntoPrimitive, Copy, Clone, Eq, PartialEq, Debug)]
#[repr(u8)]
enum Option {
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

    fn emit(&mut self, code: Option, p: &mut PacketWriter) -> Result<(), Error> {
        if !self.is_rejected {
            p.append_option(code.into(), self.address.as_bytes())?;
        }
        Ok(())
    }

    fn nacked(&mut self, data: &[u8], is_rej: bool) {
        if is_rej {
            self.is_rejected = true
        } else {
            if data.len() == 4 {
                self.address = Ipv4Address::from_bytes(data);
            } else {
                // Peer wants us to use an address that's not 4 bytes.
                // Should never happen, but mark option as rejected just in case to
                // avoid endless loop.
                self.is_rejected = true
            }
        }
    }
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
}

impl Protocol for IPv4CP {
    fn protocol(&self) -> ProtocolType {
        ProtocolType::IPv4CP
    }

    fn peer_options_start(&mut self) {}

    fn peer_option_received(&mut self, code: u8, data: &[u8]) -> Verdict {
        let opt = Option::from(code);
        log::info!("IPv4CP option {:x} {:?} {:x?}", code, opt, data);
        match opt {
            Option::IpAddress => {
                if data.len() == 4 {
                    self.peer_address = Ipv4Address::from_bytes(data);
                    Verdict::Ack
                } else {
                    Verdict::Rej
                }
            }
            _ => Verdict::Rej,
        }
    }

    fn own_options(&mut self, p: &mut PacketWriter) -> Result<(), Error> {
        self.address.emit(Option::IpAddress, p)?;
        self.dns_server_1.emit(Option::Dns1, p)?;
        self.dns_server_2.emit(Option::Dns2, p)?;
        Ok(())
    }

    fn own_option_nacked(&mut self, code: u8, data: &[u8], is_rej: bool) {
        let opt = Option::from(code);
        log::info!("IPv4CP nak {:x} {:?} {:x?} {}", code, opt, data, is_rej);
        match opt {
            Option::Unknown => {}
            Option::IpAddress => self.address.nacked(data, is_rej),
            Option::Dns1 => self.dns_server_1.nacked(data, is_rej),
            Option::Dns2 => self.dns_server_2.nacked(data, is_rej),
        }
    }
}
