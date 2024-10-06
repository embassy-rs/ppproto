#![no_std]
#![warn(missing_docs)]
#![doc = include_str!("../README.md")]

// This mod MUST go first, so that the others see its macros.
pub(crate) mod fmt;

mod ppp;
pub mod pppos;
mod wire;

pub use ppp::{Config, Ipv4Status, Phase, Status};

/// Invalid state error.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct InvalidStateError;
