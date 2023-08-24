//! PPP over Serial

mod crc;
mod frame_reader;
mod frame_writer;

use core::ops::Range;

use self::frame_reader::FrameReader;
use self::frame_writer::FrameWriter;
use crate::ppp::PPP;
use crate::wire::{Packet, ProtocolType};
use crate::{Config, Status};

pub use self::frame_writer::BufferFullError;

/// Return value from [`PPPoS::poll()`].
pub enum PPPoSAction {
    /// No action needed to take.
    None,
    /// An IP packet was received.
    ///
    /// The packet is located in `rx_buf[range]`, you must pass it to higher layers for processing.
    Received(Range<usize>),
    /// PPP wants to transmit some data.
    ///
    /// You must transmit `tx_buf[..n]` over the serial connection.
    Transmit(usize),
}

/// Main PPPoS struct.
pub struct PPPoS<'a> {
    frame_reader: FrameReader,
    ppp: PPP<'a>,
}

impl<'a> PPPoS<'a> {
    /// Create a new PPPoS
    ///
    /// The PPPoS is created in phase [`Dead`](crate::Phase::Dead), i.e. not connected. You must
    /// call [`open()`](Self::open) to get it to start connecting.
    pub fn new(config: Config<'a>) -> Self {
        Self {
            frame_reader: FrameReader::new(),
            ppp: PPP::new(config),
        }
    }

    /// Get the status of the PPPoS connection.
    pub fn status(&self) -> Status {
        self.ppp.status()
    }

    /// Start opening the PPPoS connection.
    ///
    /// This will kick off the PPP state machine.
    ///
    /// Returns an error if it's not in phase [`Dead`](crate::Phase::Dead).
    pub fn open(&mut self) -> Result<(), crate::InvalidStateError> {
        self.ppp.open()
    }

    /// Process received data and generate data to be send.
    ///
    /// The return value tells you what action to take. See [`PPPoSAction`] documentation
    /// for details.
    pub fn poll(&mut self, tx_buf: &mut [u8], rx_buf: &mut [u8]) -> PPPoSAction {
        let mut w = FrameWriter::new(tx_buf);

        let mut tx = |pkt: Packet<'_>| {
            //info!("tx: {:?}", pkt);

            let mut buf = [0; 128];
            let len = pkt.buffer_len();
            assert!(len <= buf.len());
            pkt.emit(&mut buf[..len]);

            w.start().unwrap();
            w.append(&mut buf[..len]).unwrap();
            w.finish().unwrap();
        };

        // Handle input
        if let Some(range) = self.frame_reader.receive() {
            let pkt = &mut rx_buf[range.clone()];
            let proto = u16::from_be_bytes(pkt[0..2].try_into().unwrap());
            match proto.into() {
                ProtocolType::IPv4 => return PPPoSAction::Received((range.start + 2)..range.end),
                _ => self.ppp.received(pkt, &mut tx),
            }
        }

        self.ppp.poll(tx);

        let r = w.len();
        if r == 0 {
            PPPoSAction::None
        } else {
            PPPoSAction::Transmit(r)
        }
    }

    /// Send an IP packet.
    ///
    /// You must provide enough buffer space for the data to be transmitted. This function
    /// returns the size of the encoded packet `n`, you must transmit `tx_buf[..n]` over the
    /// serial connection.
    ///
    /// Returns `BufferFullError` if `tx_buf` is too small.
    pub fn send(&mut self, pkt: &[u8], tx_buf: &mut [u8]) -> Result<usize, BufferFullError> {
        // TODO check IPv4CP is up

        let mut w = FrameWriter::new_with_asyncmap(tx_buf, self.ppp.lcp.proto().asyncmap_remote);
        let proto: u16 = ProtocolType::IPv4.into();
        w.start()?;
        w.append(&proto.to_be_bytes())?;
        w.append(pkt)?;
        w.finish()?;
        Ok(w.len())
    }

    /// Consume data received from the serial connection.
    ///
    /// After calling `consume`, `poll` must be called to process the consumed data.
    ///
    /// Returns how many bytes were actually consumed. If less than `data.len()`, `consume`
    /// must be called again with the remaining data.
    pub fn consume(&mut self, data: &[u8], rx_buf: &mut [u8]) -> usize {
        self.frame_reader.consume(rx_buf, data)
    }
}
