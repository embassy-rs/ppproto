mod crc;
mod frame_reader;
mod frame_writer;

use as_slice::AsMutSlice;
use core::convert::TryInto;
use core::ops::Range;
use crate::fmt::{assert, panic, *};

use self::frame_reader::FrameReader;
use self::frame_writer::FrameWriter;
use crate::ppp::PPP;
use crate::wire::{Packet, ProtocolType};
use crate::{Config, Status};

pub use self::frame_writer::BufferFullError;

pub enum PPPoSAction<B> {
    None,
    Received(B, Range<usize>),
    Transmit(usize),
}

pub struct PPPoS<'a, B: AsMutSlice<Element = u8>> {
    frame_reader: FrameReader,
    rx_buf: Option<B>,
    ppp: PPP<'a>,
}

impl<'a, B: AsMutSlice<Element = u8>> PPPoS<'a, B> {
    pub fn new(config: Config<'a>) -> Self {
        Self {
            frame_reader: FrameReader::new(),
            rx_buf: None,
            ppp: PPP::new(config),
        }
    }

    pub fn status(&self) -> Status {
        self.ppp.status()
    }

    pub fn open(&mut self) -> Result<(), crate::InvalidStateError> {
        self.ppp.open()
    }

    pub fn has_rx_buf(&self) -> bool {
        self.rx_buf.is_some()
    }

    pub fn put_rx_buf(&mut self, rx_buf: B) {
        if self.rx_buf.is_some() {
            panic!("called put_rx_buf when we already have a buffer.")
        }

        self.rx_buf = Some(rx_buf)
    }

    /// Process received data and generate data to be send.
    ///
    /// Action::Received is returned when an IP packet is received. You must then pass the packet
    /// to higher layers for processing.
    ///
    /// You must provide buffer space for data to be transmitted, and transmit the returned slice
    /// over the serial connection if Action::Transmit is returned.
    pub fn poll(&mut self, tx_buf: &mut [u8]) -> PPPoSAction<B> {
        let mut w = FrameWriter::new(tx_buf);

        let buf = unwrap!(self.rx_buf.as_mut(), "called poll() without an rx_buf").as_mut_slice();

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
            let pkt = &mut buf[range.clone()];
            let proto = u16::from_be_bytes(pkt[0..2].try_into().unwrap());
            match proto.into() {
                ProtocolType::IPv4 => {
                    return PPPoSAction::Received(
                        self.rx_buf.take().unwrap(),
                        (range.start + 2)..range.end,
                    )
                }
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
    /// You must provide buffer space for the data to be transmitted, and transmit the returned
    /// slice over the serial connection.
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
    pub fn consume(&mut self, data: &[u8]) -> usize {
        let buf = unwrap!(self.rx_buf.as_mut(), "called consume() without an rx_buf");
        self.frame_reader.consume(buf.as_mut_slice(), data)
    }
}
