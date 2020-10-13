use num_enum::{FromPrimitive, IntoPrimitive};

use super::options::{Protocol, Verdict};
use super::packet_writer::PacketWriter;
use super::Error;
use super::ProtocolType;

#[derive(FromPrimitive, IntoPrimitive, Copy, Clone, Eq, PartialEq, Debug)]
#[repr(u8)]
enum Option {
    #[num_enum(default)]
    Unknown = 0,
    Auth = 3,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum AuthType {
    None = 0,
    PAP = 0xc023,
}

pub(crate) struct LCP {
    pub auth: AuthType,
}

impl LCP {
    pub fn new() -> Self {
        Self {
            auth: AuthType::None,
        }
    }
}

impl Protocol for LCP {
    fn protocol(&self) -> ProtocolType {
        ProtocolType::LCP
    }

    fn peer_options_start(&mut self) {
        self.auth = AuthType::None;
    }

    fn peer_option_received(&mut self, code: u8, data: &[u8]) -> Verdict {
        let opt = Option::from(code);
        log::info!("LCP option {:x} {:?} {:x?}", code, opt, data);
        match opt {
            Option::Unknown => Verdict::Rej,
            Option::Auth => {
                if data.len() != 2 || data != &[0xc0, 0x23] {
                    return Verdict::Nack(&[0xc0, 0x23]);
                }
                self.auth = AuthType::PAP;
                Verdict::Ack
            }
        }
    }

    fn own_options(&mut self, _p: &mut PacketWriter) -> Result<(), Error> {
        Ok(())
    }
    fn own_option_nacked(&mut self, _code: u8, _data: &[u8], _is_rej: bool) {}
}
