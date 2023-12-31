// Rust version of the fasthash functions
use std::hash::Hasher;

pub struct FastHash {
    seed: u64,
}

impl FastHash {
    pub fn new(seed: u64) -> FastHash {
        FastHash { seed }
    }

    fn fasthash_mix(h: u64) -> u64 {
        let mut h = h;
        h ^= h >> 23;
        h = h.wrapping_mul(0x2127599bf4325c37);
        h ^= h >> 47;
        h
    }

    pub fn fasthash64(&self, buf: &[u8]) -> u64 {
        const M: u64 = 0x880355f21e6d1965;
        let mut h: u64 = self.seed ^ (buf.len() as u64).wrapping_mul(M);

        let mut pos = 0;
        while pos + 8 <= buf.len() {
            let v = u64::from_ne_bytes(buf[pos..pos+8].try_into().unwrap());
            h ^= Self::fasthash_mix(v);
            h = h.wrapping_mul(M);
            pos += 8;
        }

        let mut v = 0u64;
        for &byte in buf[pos..].iter().rev() {
            v = (v << 8) | byte as u64;
        }
        h ^= Self::fasthash_mix(v);
        h = h.wrapping_mul(M);

        Self::fasthash_mix(h)
    }

    pub fn fasthash32(&self, buf: &[u8]) -> u32 {
        let h = self.fasthash64(buf);
        (h - (h >> 32)) as u32
    }
}

impl Hasher for FastHash {
    fn finish(&self) -> u64 {
        self.seed
    }

    fn write(&mut self, bytes: &[u8]) {
        self.seed = self.fasthash64(bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        
    }
}
