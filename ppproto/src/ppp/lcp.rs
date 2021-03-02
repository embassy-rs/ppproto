use core::convert::TryInto;
use crate::fmt::*;
use num_enum::{FromPrimitive, IntoPrimitive};

use super::option_fsm::{Protocol, Verdict};
use crate::wire::ProtocolType;

#[derive(FromPrimitive, IntoPrimitive, Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "derive-defmt", derive(defmt::Format))]
#[repr(u8)]
enum Option {
    #[num_enum(default)]
    Unknown = 0,
    Asyncmap = 2,
    Auth = 3,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "derive-defmt", derive(defmt::Format))]
pub enum AuthType {
    None = 0,
    PAP = 0xc023,
}

pub(crate) struct LCP {
    pub auth: AuthType,

    pub asyncmap_remote: u32,
    pub asyncmap: u32,
    pub asyncmap_rej: bool,
}

impl LCP {
    pub fn new() -> Self {
        Self {
            auth: AuthType::None,
            asyncmap_remote: 0xFFFFFFFF,
            asyncmap: 0x00000000,
            asyncmap_rej: false,
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
            Option::Asyncmap => {
                if data.len() == 4 {
                    self.asyncmap_remote = u32::from_be_bytes(data.try_into().unwrap());
                    Verdict::Ack
                } else {
                    Verdict::Rej
                }
            }
            Option::Auth => {
                if data == &[0xc0, 0x23] {
                    self.auth = AuthType::PAP;
                    Verdict::Ack
                } else {
                    Verdict::Nack(&[0xc0, 0x23])
                }
            }
        }
    }

    fn own_options(&mut self, mut f: impl FnMut(u8, &[u8])) {
        if !self.asyncmap_rej {
            f(Option::Asyncmap.into(), &self.asyncmap.to_be_bytes());
        }
    }

    fn own_option_nacked(&mut self, code: u8, data: &[u8], is_rej: bool) {
        let opt = Option::from(code);
        trace!("LCP nak {:?} {:?} {:?} {:?}", code, opt, data, is_rej);
        match opt {
            Option::Asyncmap => {
                if !is_rej && data.len() == 4 {
                    self.asyncmap = u32::from_be_bytes(data.try_into().unwrap())
                } else {
                    self.asyncmap_rej = true
                }
            }
            _ => {}
        }
    }
}
