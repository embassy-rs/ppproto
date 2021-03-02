use crate::fmt::*;
use crate::fmt::{panic, *};
use heapless::consts::*;
use heapless::Vec;
use num_enum::{FromPrimitive, IntoPrimitive};

pub type MaxOptions = U6;
pub type MaxOptionLen = U4;

#[derive(FromPrimitive, IntoPrimitive, Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "derive-defmt", derive(defmt::Format))]
#[repr(u16)]
pub enum ProtocolType {
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

#[derive(
    FromPrimitive, IntoPrimitive, Copy, Clone, Eq, PartialEq, Debug, Ord, PartialOrd,
)]
#[cfg_attr(feature = "derive-defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum Code {
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

#[cfg_attr(feature = "derive-defmt", derive(defmt::Format))]
pub struct Packet<'a> {
    pub proto: ProtocolType,
    pub payload: Payload<'a>,
}

impl<'a> Packet<'a> {
    pub fn buffer_len(&self) -> usize {
        2 + self.payload.buffer_len()
    }

    pub fn emit(&self, buffer: &mut [u8]) {
        let proto = self.proto as u16;
        buffer[0..2].copy_from_slice(&proto.to_be_bytes());
        self.payload.emit(&mut buffer[2..])
    }
}

#[cfg_attr(feature = "derive-defmt", derive(defmt::Format))]
pub enum Payload<'a> {
    Raw(&'a mut [u8]),
    PPP(Code, u8, PPPPayload<'a>),
}

impl<'a> Payload<'a> {
    pub fn buffer_len(&self) -> usize {
        match self {
            Self::Raw(data) => data.len(),
            Self::PPP(_code, _id, payload) => 1 + 1 + 2 + payload.buffer_len(),
        }
    }

    pub fn emit(&self, buffer: &mut [u8]) {
        match self {
            Self::Raw(data) => buffer.copy_from_slice(data),
            Self::PPP(code, id, payload) => {
                buffer[0] = *code as u8;
                buffer[1] = *id;
                let len = payload.buffer_len() as u16 + 4;
                buffer[2..4].copy_from_slice(&len.to_be_bytes());
                payload.emit(&mut buffer[4..])
            }
        }
    }
}

#[cfg_attr(feature = "derive-defmt", derive(defmt::Format))]
pub enum PPPPayload<'a> {
    Raw(&'a mut [u8]),
    PAP(&'a [u8], &'a [u8]),
    Options(Options),
}

impl<'a> PPPPayload<'a> {
    pub fn buffer_len(&self) -> usize {
        match self {
            Self::Raw(data) => data.len(),
            Self::PAP(user, pass) => 1 + user.len() + 1 + pass.len(),
            Self::Options(options) => options.buffer_len(),
        }
    }

    pub fn emit(&self, buffer: &mut [u8]) {
        match self {
            Self::Raw(data) => buffer.copy_from_slice(data),
            Self::PAP(user, pass) => {
                buffer[0] = user.len() as u8;
                buffer[1..][..user.len()].copy_from_slice(user);
                buffer[1 + user.len()] = pass.len() as u8;
                buffer[1 + user.len() + 1..].copy_from_slice(pass);
            }
            Self::Options(options) => options.emit(buffer),
        }
    }
}

pub struct Options(pub Vec<OptionVal, MaxOptions>);

impl Options {
    pub fn buffer_len(&self) -> usize {
        self.0.iter().map(|opt| opt.buffer_len()).sum()
    }

    pub fn emit(&self, mut buffer: &mut [u8]) {
        for o in &self.0 {
            let len = o.buffer_len();
            o.emit(&mut buffer[..len]);
            buffer = &mut buffer[len..];
        }
    }
}

#[cfg(feature = "derive-defmt")]
impl defmt::Format for Options {
    fn format(&self, fmt: &mut Formatter) {
        defmt::write!(fmt, "{:[?]}", &self.0[..])
    }
}

#[cfg_attr(feature = "derive-defmt", derive(defmt::Format))]
pub struct OptionVal {
    code: u8,
    data: OptionData,
}

impl OptionVal {
    pub fn new(code: u8, data: &[u8]) -> Self {
        Self {
            code,
            data: OptionData(unwrap!(Vec::from_slice(data))),
        }
    }

    pub fn buffer_len(&self) -> usize {
        2 + self.data.0.len()
    }

    pub fn emit(&self, buffer: &mut [u8]) {
        buffer[0] = self.code;
        buffer[1] = self.data.0.len() as u8 + 2;
        buffer[2..].copy_from_slice(&self.data.0);
    }
}

struct OptionData(Vec<u8, MaxOptionLen>);

#[cfg(feature = "derive-defmt")]
impl defmt::Format for OptionData {
    fn format(&self, fmt: &mut Formatter) {
        defmt::write!(fmt, "{:[?]}", &self.0[..])
    }
}
