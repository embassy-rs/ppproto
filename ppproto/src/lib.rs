#![cfg_attr(not(feature = "std"), no_std)]

mod ppp;
pub mod pppos;
mod wire;

pub use ppp::{Config, Phase, Status};
pub use pppos::{BufferFullError, PPPoS, PPPoSAction};

#[derive(Debug, defmt::Format, PartialEq, Eq, Clone, Copy)]
pub struct InvalidStateError;
