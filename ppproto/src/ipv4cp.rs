use num_enum::{FromPrimitive, IntoPrimitive};

use super::options::{Protocol, Verdict};
use super::packet_writer::PacketWriter;
use super::{Error, ProtocolType};

#[derive(FromPrimitive, IntoPrimitive, Copy, Clone, Eq, PartialEq, Debug)]
#[repr(u8)]
enum Option {
    #[num_enum(default)]
    Unknown = 0,
    IpAddress = 3,
    Dns1 = 129,
    Dns2 = 131,
}

pub struct IPv4CP {}

impl IPv4CP {
    pub fn new() -> Self {
        Self {}
    }
}

impl Protocol for IPv4CP {
    fn protocol(&self) -> ProtocolType {
        ProtocolType::IPv4CP
    }

    fn peer_options_start(&mut self) {}

    fn peer_option_received(&mut self, code: u8, data: &[u8]) -> Verdict {
        let opt = Option::from(code);
        println!("LCP option {:x} {:?} {:x?}", code, opt, data);
        match opt {
            Option::Unknown => Verdict::Rej,
            Option::IpAddress => Verdict::Ack,
            Option::Dns1 => Verdict::Ack,
            Option::Dns2 => Verdict::Ack,
        }
    }

    fn own_options(&mut self, _p: &mut PacketWriter) -> Result<(), Error> {
        Ok(())
    }
    fn own_option_nacked(&mut self, _code: u8, _data: &[u8], _is_rej: bool) {}
}
