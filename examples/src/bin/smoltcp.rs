#[path = "../serial_port.rs"]
mod serial_port;

use as_slice::{AsMutSlice, AsSlice};
use clap::Parser;
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::marker::PhantomData;
use std::ops::Range;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::str;

use log::*;
use smoltcp::iface::{Interface, SocketSet};
use smoltcp::phy::wait as phy_wait;
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::IpCidr;

use ppproto::pppos::{PPPoS, PPPoSAction};
use ppproto::Config;
use serial_port::SerialPort;

#[derive(clap::Parser)]
struct Opts {
    #[clap(short, long)]
    device: String,
}

const MTU: usize = 1520; // IP mtu of 1500 + some margin for PPP headers.
struct Buf(Box<[u8; MTU]>);
impl Buf {
    pub fn new() -> Self {
        Self(Box::new([0; MTU]))
    }
}
impl AsSlice for Buf {
    type Element = u8;
    fn as_slice(&self) -> &[Self::Element] {
        &*self.0
    }
}
impl AsMutSlice for Buf {
    fn as_mut_slice(&mut self) -> &mut [Self::Element] {
        &mut *self.0
    }
}

type PPP = PPPoS<'static, Buf>;

struct PPPDevice {
    ppp: PPP,
    port: SerialPort,
}

impl PPPDevice {
    fn new(ppp: PPP, port: SerialPort) -> Self {
        Self { ppp, port }
    }
}

impl Device for PPPDevice {
    type RxToken<'a> = PPPRxToken<'a>;
    type TxToken<'a> = PPPTxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.port.set_nonblocking(true).unwrap();

        let mut tx_buf = [0; 2048];

        let mut read_buf = [0; 2048];
        let mut data: &[u8] = &[];
        loop {
            // Poll the ppp
            match self.ppp.poll(&mut tx_buf) {
                PPPoSAction::None => {}
                PPPoSAction::Transmit(n) => self.port.write_all(&tx_buf[..n]).unwrap(),
                PPPoSAction::Received(buf, range) => {
                    self.ppp.put_rx_buf(Buf::new());
                    return Some((
                        PPPRxToken {
                            buf,
                            range,
                            _phantom: PhantomData,
                        },
                        PPPTxToken {
                            port: &mut self.port,
                            ppp: &mut self.ppp,
                        },
                    ));
                }
            }

            // If we have no data, read some.
            if data.len() == 0 {
                let n = match self.port.read(&mut read_buf) {
                    Ok(n) => n,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return None,
                    Err(e) => panic!("error reading: {:?}", e),
                };
                data = &read_buf[..n];
            }

            // Consume some data, saving the rest for later
            let n = self.ppp.consume(data);
            data = &data[n..];
        }
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(PPPTxToken {
            port: &mut self.port,
            ppp: &mut self.ppp,
        })
    }

    /// Get a description of device capabilities.
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps: DeviceCapabilities = Default::default();
        caps.max_transmission_unit = 1500;
        caps.medium = Medium::Ip;
        caps
    }
}

struct PPPRxToken<'a> {
    buf: Buf,
    range: Range<usize>,
    _phantom: PhantomData<&'a mut PPP>,
}

impl<'a> RxToken for PPPRxToken<'a> {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.buf.0[self.range])
    }
}

struct PPPTxToken<'a> {
    port: &'a mut SerialPort,
    ppp: &'a mut PPP,
}

impl<'a> TxToken for PPPTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut pkt_buf = [0; 2048];
        let pkt = &mut pkt_buf[..len];
        let r = f(pkt);

        let mut tx_buf = [0; 2048];
        let n = self.ppp.send(pkt, &mut tx_buf).unwrap();

        // not sure if this is necessary
        self.port.set_nonblocking(false).unwrap();

        self.port.write_all(&tx_buf[..n]).unwrap();

        r
    }
}

fn main() {
    env_logger::init();

    let opts: Opts = Opts::parse();

    let port = SerialPort::new(Path::new(&opts.device)).unwrap();
    let fd = port.as_raw_fd();

    let config = Config {
        username: b"myuser",
        password: b"mypass",
    };
    let mut ppp = PPPoS::new(config);

    ppp.put_rx_buf(Buf::new());

    ppp.open().unwrap();

    let mut device = PPPDevice::new(ppp, port);

    let udp_rx_buffer = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY], vec![0; 64]);
    let udp_tx_buffer = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY], vec![0; 128]);
    let udp_socket = udp::Socket::new(udp_rx_buffer, udp_tx_buffer);

    let tcp1_rx_buffer = tcp::SocketBuffer::new(vec![0; 64]);
    let tcp1_tx_buffer = tcp::SocketBuffer::new(vec![0; 128]);
    let tcp1_socket = tcp::Socket::new(tcp1_rx_buffer, tcp1_tx_buffer);

    let tcp2_rx_buffer = tcp::SocketBuffer::new(vec![0; 64]);
    let tcp2_tx_buffer = tcp::SocketBuffer::new(vec![0; 128]);
    let tcp2_socket = tcp::Socket::new(tcp2_rx_buffer, tcp2_tx_buffer);

    let tcp3_rx_buffer = tcp::SocketBuffer::new(vec![0; 65535]);
    let tcp3_tx_buffer = tcp::SocketBuffer::new(vec![0; 65535]);
    let tcp3_socket = tcp::Socket::new(tcp3_rx_buffer, tcp3_tx_buffer);

    let tcp4_rx_buffer = tcp::SocketBuffer::new(vec![0; 65535]);
    let tcp4_tx_buffer = tcp::SocketBuffer::new(vec![0; 65535]);
    let tcp4_socket = tcp::Socket::new(tcp4_rx_buffer, tcp4_tx_buffer);

    let mut config = smoltcp::iface::Config::new(smoltcp::wire::HardwareAddress::Ip);
    config.random_seed = rand::random();
    let mut iface = Interface::new(config, &mut device, Instant::now());

    let mut sockets = SocketSet::new(vec![]);
    let udp_handle = sockets.add(udp_socket);
    let tcp1_handle = sockets.add(tcp1_socket);
    let tcp2_handle = sockets.add(tcp2_socket);
    let tcp3_handle = sockets.add(tcp3_socket);
    let tcp4_handle = sockets.add(tcp4_socket);

    let mut tcp_6970_active = false;
    loop {
        let timestamp = Instant::now();
        iface.poll(timestamp, &mut device, &mut sockets);

        let status = device.ppp.status();

        if let Some(ipv4) = status.ipv4 {
            if let Some(want_addr) = ipv4.address {
                // convert to smoltcp
                let want_addr = smoltcp::wire::Ipv4Address::from_bytes(&want_addr.0);
                iface.update_ip_addrs(|addrs| {
                    if addrs.len() != 1 || addrs[0].address() != want_addr.into() {
                        addrs.clear();
                        addrs.push(IpCidr::new(want_addr.into(), 0)).unwrap();
                        info!("Assigned a new IPv4 address: {}", want_addr);
                    }
                });
            }
        }

        // udp:6969: respond "hello"
        {
            let socket = sockets.get_mut::<udp::Socket>(udp_handle);
            if !socket.is_open() {
                socket.bind(6969).unwrap()
            }

            let client = match socket.recv() {
                Ok((data, endpoint)) => {
                    debug!(
                        "udp:6969 recv data: {:?} from {}",
                        str::from_utf8(data.as_ref()).unwrap(),
                        endpoint
                    );
                    Some(endpoint)
                }
                Err(_) => None,
            };
            if let Some(endpoint) = client {
                let data = b"hello\n";
                debug!(
                    "udp:6969 send data: {:?}",
                    str::from_utf8(data.as_ref()).unwrap()
                );
                socket.send_slice(data, endpoint).unwrap();
            }
        }

        // tcp:6969: respond "hello"
        {
            let socket = sockets.get_mut::<tcp::Socket>(tcp1_handle);
            if !socket.is_open() {
                socket.listen(6969).unwrap();
            }

            if socket.can_send() {
                debug!("tcp:6969 send greeting");
                write!(socket, "hello\n").unwrap();
                debug!("tcp:6969 close");
                socket.close();
            }
        }

        // tcp:6970: echo with reverse
        {
            let socket = sockets.get_mut::<tcp::Socket>(tcp2_handle);
            if !socket.is_open() {
                socket.listen(6970).unwrap()
            }

            if socket.is_active() && !tcp_6970_active {
                debug!("tcp:6970 connected");
            } else if !socket.is_active() && tcp_6970_active {
                debug!("tcp:6970 disconnected");
            }
            tcp_6970_active = socket.is_active();

            if socket.may_recv() {
                let data = socket
                    .recv(|buffer| {
                        let recvd_len = buffer.len();
                        let mut data = buffer.to_owned();
                        if data.len() > 0 {
                            debug!(
                                "tcp:6970 recv data: {:?}",
                                str::from_utf8(data.as_ref()).unwrap_or("(invalid utf8)")
                            );
                            data = data.split(|&b| b == b'\n').collect::<Vec<_>>().concat();
                            data.reverse();
                            data.extend(b"\n");
                        }
                        (recvd_len, data)
                    })
                    .unwrap();
                if socket.can_send() && data.len() > 0 {
                    debug!(
                        "tcp:6970 send data: {:?}",
                        str::from_utf8(data.as_ref()).unwrap_or("(invalid utf8)")
                    );
                    socket.send_slice(&data[..]).unwrap();
                }
            } else if socket.may_send() {
                debug!("tcp:6970 close");
                socket.close();
            }
        }

        // tcp:6971: sinkhole
        {
            let socket = sockets.get_mut::<tcp::Socket>(tcp3_handle);
            if !socket.is_open() {
                socket.listen(6971).unwrap();
                socket.set_keep_alive(Some(Duration::from_millis(1000)));
                socket.set_timeout(Some(Duration::from_millis(2000)));
            }

            if socket.may_recv() {
                socket
                    .recv(|buffer| {
                        if buffer.len() > 0 {
                            debug!("tcp:6971 recv {:?} octets", buffer.len());
                        }
                        (buffer.len(), ())
                    })
                    .unwrap();
            } else if socket.may_send() {
                socket.close();
            }
        }

        // tcp:6972: fountain
        {
            let socket = sockets.get_mut::<tcp::Socket>(tcp4_handle);
            if !socket.is_open() {
                socket.listen(6972).unwrap()
            }

            if socket.may_send() {
                socket
                    .send(|data| {
                        if data.len() > 0 {
                            debug!("tcp:6972 send {:?} octets", data.len());
                            for (i, b) in data.iter_mut().enumerate() {
                                *b = (i % 256) as u8;
                            }
                        }
                        (data.len(), ())
                    })
                    .unwrap();
            }
        }

        phy_wait(fd, iface.poll_delay(timestamp, &sockets)).expect("wait error");
    }
}
