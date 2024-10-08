# ppproto

Rust implementation of the Point-to-Point Protocol (PPP) for embedded systems. `no-std` compatible, no alloc (heap) required.

## Relevant RFCs

- [RFC 1661](https://tools.ietf.org/html/rfc1661) - The Point-to-Point Protocol (PPP)
- [RFC 1332](https://tools.ietf.org/html/rfc1332) - The PPP Internet Protocol Control Protocol (IPCP)
- [RFC 1334](https://tools.ietf.org/html/rfc1334) - PPP Authentication Protocols

## Testing against pppd

Put this in `/etc/ppp/pap-secrets`, where `myhostname` is the hostname of your machine.

```txt
myuser myhostname mypass 192.168.7.10
```

```sh
socat -v -x PTY,link=pty1,rawer PTY,link=pty2,rawer
pppd $PWD/pty1 115200 192.168.7.1: ms-dns 8.8.4.4 ms-dns 8.8.8.8 nodetach debug local persist silent noproxyarp
RUST_LOG=trace cargo run --bin simple -- --device pty2
ping 192.168.7.10
```

## Testing against a real modem

- `minicom -D /dev/ttyUSB0 -b 115200`
- put whatever AT commands you need to connect (such as `ATD*99#`)
- Control+A Q
- RUST_LOG=trace cargo run --bin simple -- --device /dev/ttyUSB0

If you want to "MITM" the serial communications to see the raw bytes coming and going, you can do this:

```sh
socat -v -x /dev/ttyUSB0 PTY,link=pty,rawer
```

and then use `$PWD/pty` instead of `/dev/ttyUSB0`

## License

This work is licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
