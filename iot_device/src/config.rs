const fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

const fn parse_key_count(s: &str) -> usize {
    let bytes = s.as_bytes();
    let mut n = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if b >= b'0' && b <= b'9' {
            n = n * 10 + (b - b'0') as usize;
        }
        i += 1;
    }
    if n == 0 { 16 } else { n } // default
}

const MAX_KEYS: usize = parse_key_count(match option_env!("KEY_COUNT") {
    Some(v) => v,
    None => "",
});

const fn parse_keys256(s: &str) -> ([[u8; 32]; MAX_KEYS], usize) {
    let mut keys = [[0u8; 32]; MAX_KEYS];
    let mut count = 0usize;

    if s.as_bytes().is_empty() {
        return (keys, 0);
    }

    let bytes = s.as_bytes();
    let mut cur = [0u8; 32];
    let mut nibble_idx = 0usize; 
    let mut i = 0usize;

    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b',' => {
                if count < MAX_KEYS {
                    keys[count] = cur;
                    count += 1;
                }
                cur = [0u8; 32];
                nibble_idx = 0;
            }
            b'x' | b'X' => {}
            _ => {
                if nibble_idx < 64 {
                    let v = hex_val(b);
                    let byte_idx = nibble_idx / 2;
                    if nibble_idx % 2 == 0 {
                        cur[byte_idx] = v << 4;
                    } else {
                        cur[byte_idx] |= v;
                    }
                    nibble_idx += 1;
                }
            }
        }
        i += 1;
    }

    if count < MAX_KEYS {
        keys[count] = cur;
        count += 1;
    }

    (keys, count)
}

static KEYS_RAW: ([[u8; 32]; MAX_KEYS], usize) = parse_keys256(match option_env!("KEYS") {
    Some(val) => val,
    None => "",
});

static SKEY: &'static [u8] = match option_env!("SKEY") {
    Some(val) => val.as_bytes(),
    None => b"",
};

pub fn read_initial_keys() -> &'static [[u8; 32]] { &KEYS_RAW.0[..KEYS_RAW.1] }
pub fn read_skey() -> &'static [u8] { SKEY }