#[path = "../serial_port.rs"]
mod serial_port;

use clap::Parser;
use std::io::{Read, Write};
use std::path::Path;

use ppproto::{Config, PPPoS, PPPoSAction};
use serial_port::SerialPort;

#[derive(Parser)]
struct Opts {
    #[clap(short, long)]
    device: String,
}

fn main() {
    env_logger::init();

    let opts: Opts = Opts::parse();
    let mut port = SerialPort::new(Path::new(&opts.device)).unwrap();

    let config = Config {
        username: b"myuser",
        password: b"mypass",
    };
    let mut ppp = PPPoS::new(config);

    let mut rx_buf = [0; 2048];
    ppp.put_rx_buf(&mut rx_buf);

    ppp.open().unwrap();

    let mut tx_buf = [0; 2048];

    let mut read_buf = [0; 2048];
    let mut data: &[u8] = &[];
    loop {
        // Poll the ppp
        match ppp.poll(&mut tx_buf) {
            PPPoSAction::None => {}
            PPPoSAction::Transmit(n) => port.write_all(&tx_buf[..n]).unwrap(),
            PPPoSAction::Received(rx_buf, range) => {
                let pkt = &mut rx_buf[range];
                log::info!("received packet: {:x?}", pkt);

                // Toy code to reply to pings with no error handling whatsoever.
                let header_len = (pkt[0] & 0x0f) as usize * 4;
                let proto = pkt[9];
                if proto == 1 {
                    // ICMP packet
                    let icmp_type = pkt[header_len];
                    let icmp_code = pkt[header_len + 1];

                    if icmp_type == 8 && icmp_code == 0 {
                        // ICMP Echo Request

                        // Transform to echo response
                        pkt[header_len] = 0;

                        // Fix checksum
                        pkt[header_len + 2] = 0;
                        pkt[header_len + 3] = 0;
                        let c = !checksum(&pkt[header_len..]);
                        pkt[header_len + 2..][..2].copy_from_slice(&c.to_be_bytes());

                        // Swap source and dest addressses
                        let mut src_addr = [0; 4];
                        let mut dst_addr = [0; 4];
                        src_addr.copy_from_slice(&pkt[12..16]);
                        dst_addr.copy_from_slice(&pkt[16..20]);
                        pkt[12..16].copy_from_slice(&dst_addr);
                        pkt[16..20].copy_from_slice(&src_addr);

                        // Send it!
                        let n = ppp.send(&pkt, &mut tx_buf).unwrap();
                        port.write_all(&tx_buf[..n]).unwrap();

                        log::info!("replied to ping!");
                    }
                }

                ppp.put_rx_buf(rx_buf);
            }
        }

        // If we have no data, read some.
        if data.len() == 0 {
            let n = port.read(&mut read_buf).unwrap();
            data = &read_buf[..n];
        }

        // Consume some data, saving the rest for later
        let n = ppp.consume(data);
        data = &data[n..];
    }
}

fn propagate_carries(word: u32) -> u16 {
    let sum = (word >> 16) + (word & 0xffff);
    ((sum >> 16) as u16) + (sum as u16)
}

/// Compute an RFC 1071 compliant checksum (without the final complement).
fn checksum(data: &[u8]) -> u16 {
    let mut accum = 0;

    for c in data.chunks(2) {
        let x = if c.len() == 2 {
            (c[0] as u32) << 8 | (c[1] as u32)
        } else {
            (c[0] as u32) << 8
        };

        accum += x;
    }

    propagate_carries(accum)
}
