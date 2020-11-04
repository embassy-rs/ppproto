use anyfmt::*;
use num_enum::{FromPrimitive, IntoPrimitive};

use super::options::{Protocol, Verdict};
use super::packet_writer::PacketWriter;
use super::Error;
use super::ProtocolType;

#[derive(FromPrimitive, IntoPrimitive, Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
enum Option {
    #[num_enum(default)]
    Unknown = 0,
    Asyncmap = 2,
    Auth = 3,
    Magic = 5,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum AuthType {
    None = 0,
    PAP = 0xc023,
}

pub(crate) struct LCP {
    pub auth: AuthType,
    pub asyncmap: u32,
    pub magic: u32,
}

impl LCP {
    pub fn new() -> Self {
        Self {
            auth: AuthType::None,
            asyncmap: 0xFFFFFFFF,
            magic: 0x00000000,
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
        trace!("LCP: rx option {:?} {:?} {:?}", code, opt, data);
        match opt {
            Option::Unknown => Verdict::Rej,
            Option::Asyncmap => Verdict::Ack,
            Option::Magic => Verdict::Ack,
            Option::Auth => {
                if data.len() != 2 || data != &[0xc0, 0x23] {
                    return Verdict::Nack(&[0xc0, 0x23]);
                }
                self.auth = AuthType::PAP;
                Verdict::Ack
            }
        }
    }

    fn own_options(&mut self, p: &mut PacketWriter) -> Result<(), Error> {
        p.append_option(Option::Asyncmap.into(), &[0x00, 0x00, 0x00, 0x00])?;
        p.append_option(Option::Magic.into(), &[0x12, 0x34, 0x56, 0x78])?;
        Ok(())
    }
    fn own_option_nacked(&mut self, _code: u8, _data: &[u8], _is_rej: bool) {}
}
