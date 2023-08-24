#![cfg_attr(not(feature = "std"), no_std)]

// This mod MUST go first, so that the others see its macros.
pub(crate) mod fmt;

mod ppp;
pub mod pppos;
mod wire;

pub use ppp::{Config, Ipv4Address, Ipv4Status, Phase, Status};
pub use pppos::{BufferFullError, PPPoS, PPPoSAction};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct InvalidStateError;
