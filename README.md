# ppproto

Rust implementation of the Point-to-Point Protocol (PPP) for embedded systems. `no-std` compatible, no alloc (heap) required.

## Relevant RFCs

- [RFC 1661](https://tools.ietf.org/html/rfc1661) - The Point-to-Point Protocol (PPP)
- [RFC 1332](https://tools.ietf.org/html/rfc1332) - The PPP Internet Protocol Control Protocol (IPCP)
- [RFC 1334](https://tools.ietf.org/html/rfc1334) - PPP Authentication Protocols

## Testing against pppd

```
socat -v -x PTY,link=pty1,rawer PTY,link=pty2,rawer
pppd $PWD/pty1 115200 192.168.7.1:192.168.7.2 nodetach debug local persist silent noproxyarp
cargo run -p example  -- --device pty2
ping 192.168.7.2
```
