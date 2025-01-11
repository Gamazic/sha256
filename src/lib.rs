use std::fmt::Write;

const H: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub fn sha256hex(msg: &[u8]) -> String {
    return hex(&sha256(msg));
}

fn hex(bytes: &[u8; 32]) -> String {
    let mut hex_string = String::with_capacity(64);
    for byte in bytes {
        write!(&mut hex_string, "{:02x}", byte).expect("failed to write hex of byte");
    }
    return hex_string;
}

pub fn sha256(msg: &[u8]) -> [u8; 32] {
    let padded = padded_msg(msg);
    let n_blocks = padded.len() / 64;
    let mut state = H;
    for i in 0..n_blocks {
        update_state_with_block(&padded[(64*i)..(64*(i+1))], &mut state);
    }
    let mut result = [0u8; 32];
    for i in 0..8 {
        result[(4 * i)..(4 * (i + 1))].copy_from_slice(&state[i].to_be_bytes());
    }
    return result;
}


fn padded_msg(msg: &[u8]) -> Vec<u8> {
    let pad_size = {
        let rem = msg.len() % 64;
        if rem < 56 {
            64 - rem
        } else {
            64 - rem + 64
        }
    };
    let num_zeros = pad_size - 9;

    let mut msg_padded = Vec::with_capacity(msg.len() + num_zeros);
    msg_padded.extend_from_slice(msg);
    msg_padded.push(128u8);
    msg_padded.resize(msg_padded.len() + num_zeros, 0u8);
    let size = (msg.len() * 8) as u64;
    msg_padded.extend(size.to_be_bytes());
    return msg_padded;
}

fn update_state_with_block(msg_block: &[u8], state: &mut [u32; 8]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes(msg_block[i * 4..(i+1)*4].try_into()
            .expect("expected block size 64"));
    }
    for i in 16..64 {
        w[i] = sigma1(w[i-2])
            .wrapping_add(w[i-7])
            .wrapping_add(sigma0(w[i-15]))
            .wrapping_add(w[i-16]);
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    for i in 0..64 {
        let t1 = h.wrapping_add(big_sigma1(e))
            .wrapping_add(ch(e,f,g))
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let t2 = big_sigma0(a).wrapping_add(maj(a,b,c));
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

fn ch(x: u32, y: u32, z: u32) -> u32 {
    return (x & y) ^ (!x & z);
}

fn maj(x: u32, y: u32, z: u32) -> u32 {
    return (x & y) ^ (x & z) ^ (y & z);
}

fn big_sigma0(x: u32) -> u32 {
    return x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22);
}

fn big_sigma1(x: u32) -> u32 {
    return x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25);
}

fn sigma0(x: u32) -> u32 {
    return x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3);
}

fn sigma1(x: u32) -> u32 {
    return x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10);
}
