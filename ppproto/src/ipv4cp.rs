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

pub(crate) struct IPv4CP {
    address: Ipv4Address,
    peer_address: Ipv4Address,
    dns_server_1: Ipv4Address,
    dns_server_2: Ipv4Address,
}

impl IPv4CP {
    pub fn new() -> Self {
        Self {
            address: Ipv4Address::UNSPECIFIED,
            peer_address: Ipv4Address::UNSPECIFIED,
            dns_server_1: Ipv4Address::UNSPECIFIED,
            dns_server_2: Ipv4Address::UNSPECIFIED,
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
            Option::Unknown => Verdict::Rej,
            Option::IpAddress => handle_ip_option(&mut self.peer_address, data),
            Option::Dns1 => Verdict::Ack,
            Option::Dns2 => Verdict::Ack,
        }
    }

    fn own_options(&mut self, p: &mut PacketWriter) -> Result<(), Error> {
        p.append_option(Option::IpAddress.into(), self.address.as_bytes())?;
        p.append_option(Option::Dns1.into(), self.dns_server_1.as_bytes())?;
        p.append_option(Option::Dns2.into(), self.dns_server_2.as_bytes())?;
        Ok(())
    }
    fn own_option_nacked(&mut self, code: u8, data: &[u8], is_rej: bool) {
        let opt = Option::from(code);
        log::info!("IPv4CP nak {:x} {:?} {:x?} {}", code, opt, data, is_rej);
        match opt {
            Option::Unknown => {}
            Option::IpAddress => handle_ip_option_nack(&mut self.address, data),
            Option::Dns1 => handle_ip_option_nack(&mut self.dns_server_1, data),
            Option::Dns2 => handle_ip_option_nack(&mut self.dns_server_2, data),
        }
    }
}

fn handle_ip_option<'a>(dst: &'a mut Ipv4Address, data: &[u8]) -> Verdict<'a> {
    if data.len() == 4 {
        *dst = Ipv4Address::from_bytes(data);
        Verdict::Ack
    } else {
        Verdict::Rej
    }
}

fn handle_ip_option_nack<'a>(dst: &'a mut Ipv4Address, data: &[u8]) {
    if data.len() == 4 {
        *dst = Ipv4Address::from_bytes(data);
    }
}
