const fn parse_keys(s: &str) -> ([u16; 32], usize) {
    if s.as_bytes().is_empty() {
        return ([0u16; 32], 0);
    }

    let bytes = s.as_bytes();
    let mut keys = [0u16; 32];
    let mut count = 0usize;
    let mut acc = 0u16;
    let mut i = 0usize;

    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b'0'..=b'9' => acc = acc * 16 + (b - b'0') as u16,
            b'a'..=b'f' => acc = acc * 16 + (b - b'a' + 10) as u16,
            b'A'..=b'F' => acc = acc * 16 + (b - b'A' + 10) as u16,
            b'x' | b'X' => {}
            b',' => {
                if count < 32 { keys[count] = acc; count += 1; }
                acc = 0;
            }
            _ => {}
        }
        i += 1;
    }

    if count < 32 { keys[count] = acc; count += 1; }

    (keys, count)
}

static KEYS_RAW: ([u16; 32], usize) = parse_keys(match option_env!("KEYS") {
    Some(val) => val,
    None => "",
});

static SKEY: &'static str = match option_env!("SKEY") {
    Some(val) => val,
    None => "",
};

pub fn read_initial_keys() -> &'static [u16] { &KEYS_RAW.0[..KEYS_RAW.1] }
pub fn read_skey() -> &'static str { SKEY }