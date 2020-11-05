#[path = "../serial_port.rs"]
mod serial_port;

use async_io::Async;
use clap::Clap;
use futures::io::BufReader;
use futures::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};
use std::io::{Read, Write};
use std::path::Path;
use std::pin::Pin;

use ppproto::{Action, Config, Error, PPP};
use serial_port::SerialPort;

#[derive(Clap)]
struct Opts {
    #[clap(short, long)]
    device: String,
}

async fn run_main() {
    let opts: Opts = Opts::parse();

    let s = SerialPort::new(Path::new(&opts.device)).unwrap();
    let s = Async::new(s).unwrap();
    let mut s = BufReader::new(s);

    let config = Config {
        username: b"myuser",
        password: b"mypass",
    };

    let mut rx_buf = [0; 2048];
    let mut ppp = PPP::new(config, &mut rx_buf);
    ppp.open().unwrap();

    let mut tx_buf = [0; 2048];

    loop {
        // Poll the ppp
        match ppp.poll(&mut tx_buf).unwrap() {
            Action::None => {}
            Action::Transmit(x) => s.write_all(x).await.unwrap(),
            Action::Received(pkt, _sender) => log::info!("received packet: {:x?}", pkt),
        }

        // Consume some data
        let buf = s.fill_buf().await.unwrap();
        let n = ppp.consume(buf);
        Pin::new(&mut s).consume(n);
    }
}

fn main() {
    env_logger::init();
    futures::executor::block_on(run_main());
}
