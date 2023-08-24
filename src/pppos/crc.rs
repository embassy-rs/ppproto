pub fn crc16(mut seed: u16, data: &[u8]) -> u16 {
    for &b in data {
        let e = seed as u8 ^ b;
        let f = e ^ (e << 4);
        let f = f as u16;
        seed = (seed >> 8) ^ (f << 8) ^ (f << 3) ^ (f >> 4);
    }
    seed
}
