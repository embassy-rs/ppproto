use super::crc::crc16;

#[derive(Copy, Clone, Debug)]
enum State {
    Start,
    Address,
    Data,
    Complete,
}

pub struct FrameReader<'a> {
    state: State,
    escape: bool,
    len: usize,
    buf: &'a mut [u8],
}

impl<'a> FrameReader<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self {
            state: State::Start,
            escape: false,
            len: 0,
            buf,
        }
    }

    pub fn receive(&mut self) -> Option<&mut [u8]> {
        match self.state {
            State::Complete => {
                let len = self.len;
                self.len = 0;
                self.state = State::Address;
                Some(&mut self.buf[1..len - 2])
            }
            _ => None,
        }
    }

    pub fn consume(&mut self, data: &[u8]) -> usize {
        for (i, &b) in data.iter().enumerate() {
            match (self.state, b) {
                (State::Start, 0x7e) => self.state = State::Address,
                (State::Start, _) => {}
                (State::Address, 0xff) => self.state = State::Data,
                (State::Address, 0x7e) => self.state = State::Address,
                (State::Address, _) => self.state = State::Start,
                (State::Data, 0x7e) => {
                    // End of packet
                    let ok = self.len >= 3
                        && self.buf[0] == 0x03
                        && crc16(0x00FF, &self.buf[..self.len]) == 0xf0b8;
                    self.state = if ok { State::Complete } else { State::Address }
                }
                (State::Data, 0x7d) => self.escape = true,
                (State::Data, mut b) => {
                    if self.escape {
                        self.escape = false;
                        b ^= 0x20;
                    }
                    if self.len == usize::MAX || self.len >= self.buf.len() {
                        self.state = State::Start;
                        self.len = 0;
                    } else {
                        self.buf[self.len as usize] = b;
                        self.len += 1;
                    }
                }
                // When we have received a frame, do not consume more data until it's processed with receive()
                (State::Complete, _) => return i,
            }
        }

        // All consumed
        data.len()
    }
}
