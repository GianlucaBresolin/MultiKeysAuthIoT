// Runtime parser that accepts a JSON-like array of base64 keys
// Example: ["b64key1","b64key2"]
// Decodes each base64 entry into 32-byte keys.

#![allow(clippy::needless_range_loop)]

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;
use alloc::string::String;
use core::ptr;

// Helper: trim JSON array brackets and quotes, split on commas, trim spaces
fn split_json_array(s: &str) -> Vec<&str> {
    let mut v: Vec<&str> = Vec::new();
    if s.is_empty() {
        return v;
    }
    // remove surrounding [ ] if present
    let mut start = 0usize;
    let mut end = s.len();
    let bytes = s.as_bytes();
    if bytes[start] == b'[' { start += 1; }
    if end > 0 && bytes[end-1] == b']' { end -= 1; }
    let inner = &s[start..end];

    // Now iterate and split by commas, but allow spaces. We'll also strip surrounding quotes from each token
    let mut i = 0usize;
    let inner_bytes = inner.as_bytes();
    let len = inner_bytes.len();
    let mut token_start = 0usize;
    while i <= len {
        if i == len || inner_bytes[i] == b',' {
            let mut tok = &inner[token_start..i];
            // trim whitespace
            tok = tok.trim();
            // strip surrounding quotes
            if tok.len() >= 2 && ((tok.as_bytes()[0] == b'"' && tok.as_bytes()[tok.len()-1] == b'"') || (tok.as_bytes()[0] == b'\'' && tok.as_bytes()[tok.len()-1] == b'\'')) {
                tok = &tok[1..tok.len()-1];
            }
            if !tok.is_empty() {
                v.push(tok);
            }
            token_start = i + 1;
        }
        i += 1;
    }
    v
}

// Simple base64 decoder (handles standard base64 with '=' padding)
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut map = [255u8; 256];
    // A-Z
    for (i, b) in (b'A'..=b'Z').enumerate() { map[b as usize] = i as u8; }
    // a-z
    for (i, b) in (b'a'..=b'z').enumerate() { map[b as usize] = (i + 26) as u8; }
    // 0-9
    for (i, b) in (b'0'..=b'9').enumerate() { map[b as usize] = (i + 52) as u8; }
    map[b'+' as usize] = 62;
    map[b'/' as usize] = 63;

    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::new();
    let mut chunk: [u8;4] = [0;4];
    let mut idx = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'=' {
            // padding - treat accordingly
            chunk[idx] = 0;
            idx += 1;
            i += 1;
        } else if b.is_ascii_whitespace() {
            i += 1;
            continue;
        } else {
            let val = map[b as usize];
            if val == 255 { return None; }
            chunk[idx] = val;
            idx += 1;
            i += 1;
        }
        if idx == 4 {
            let b0 = (chunk[0] << 2) | (chunk[1] >> 4);
            let b1 = (chunk[1] << 4) | (chunk[2] >> 2);
            let b2 = (chunk[2] << 6) | chunk[3];
            out.push(b0);
            // check original chars for padding to decide whether push b1/b2
            // To determine padding, inspect s at positions i-2 and i-1 (may be '='). Simpler: count padding in last processed 4 chars
            // But we didn't keep original chars; instead, recompute padding by looking ahead in bytes slice
            // Simpler robust approach: read the original 4 chars from bytes slice directly
            // Calculate start index of this quartet in original string
            // However for simplicity, we'll check actual base64 string for '=' in the last 2 positions relative to i
            let start_q = i.saturating_sub(4);
            let pad1 = if start_q + 2 < bytes.len() && bytes[start_q+2] == b'=' { true } else { false };
            let pad2 = if start_q + 3 < bytes.len() && bytes[start_q+3] == b'=' { true } else { false };
            if !pad1 {
                out.push(b1);
            }
            if !pad2 {
                out.push(b2);
            }
            idx = 0;
        }
    }
    // Handle remaining if any (should not happen in valid base64)
    Some(out)
}

fn parse_keys_from_json_base64(s: &str) -> Vec<[u8;32]> {
    let parts = split_json_array(s);
    let mut res: Vec<[u8;32]> = Vec::new();
    for p in parts {
        if p.is_empty() { continue; }
        if let Some(bytes) = base64_decode(p) {
            if bytes.len() == 32 {
                let mut arr = [0u8;32];
                for i in 0..32 { arr[i] = bytes[i]; }
                res.push(arr);
            } else if bytes.len() < 32 {
                // pad with zeros if shorter
                let mut arr = [0u8;32];
                for i in 0..bytes.len() { arr[i] = bytes[i]; }
                res.push(arr);
            } else {
                // truncate if longer
                let mut arr = [0u8;32];
                for i in 0..32 { arr[i] = bytes[i]; }
                res.push(arr);
            }
        }
    }
    res
}

// Globals stored as leaked boxed slices for 'static lifetime
static mut KEYS_PTR: *const [ [u8;32] ] = ptr::null();
static mut SKEY_PTR: *const [u8;32] = ptr::null();

pub fn read_initial_keys() -> &'static [[u8; 32]] {
    unsafe {
        if !KEYS_PTR.is_null() {
            &*KEYS_PTR
        } else {
            let s = match option_env!("KEYS") { Some(v) => v, None => "" };
            let vec = parse_keys_from_json_base64(s);
            let boxed: Box<[[u8;32]]> = vec.into_boxed_slice();
            let ptr = Box::into_raw(boxed);
            KEYS_PTR = ptr;
            &*KEYS_PTR
        }
    }
}

pub fn read_skey() -> &'static [u8; 32] {
    unsafe {
        if !SKEY_PTR.is_null() {
            &*SKEY_PTR
        } else {
            let s = match option_env!("SKEY") { Some(v) => v, None => "" };
            let mut arr = [0u8;32];
            if let Some(bytes) = base64_decode(s) {
                let n = core::cmp::min(32, bytes.len());
                for i in 0..n { arr[i] = bytes[i]; }
            }
            // allocate boxed array and leak
            let boxed = Box::new(arr);
            let ptr = Box::into_raw(boxed);
            SKEY_PTR = ptr as *const [u8;32];
            &*SKEY_PTR
        }
    }
}

pub fn read_iot_uid() -> u8 {
    match option_env!("IOT_UID") {
        Some(v) => {
            let s = v.as_bytes();
            let mut n: u8 = 0;
            for &b in s {
                if b >= b'0' && b <= b'9' {
                    n = n.saturating_mul(10).saturating_add(b - b'0');
                }
            }
            if n == 0 { 1 } else { n }
        }
        None => 1,
    }
}

pub fn read_p() -> u8 {
    match option_env!("P") {
        Some(v) => {
            let s = v.as_bytes();
            let mut n: u8 = 0;
            for &b in s {
                if b >= b'0' && b <= b'9' {
                    n = n.saturating_mul(10).saturating_add(b - b'0');
                }
            }
            if n == 0 { 2 } else { n }
        }
        None => 2,
    }
}

pub fn read_initial_keys() -> &'static [[u8; 32]] { &KEYS.0[..KEYS.1] }
pub fn read_skey() -> &'static [u8; 32] { &SKEY }
pub fn read_iot_uid() -> u8 { IOT_UID }
pub fn read_p() -> u8 { P_VAL }