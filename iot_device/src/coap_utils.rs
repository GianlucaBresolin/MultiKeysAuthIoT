
pub fn build_coap_non_post(message_id: u16, payload: &[u8], out: &mut [u8]) -> Option<usize> {
    if out.len() < 5 + payload.len() {
        return None;
    }
 
    out[0] = 0x50; // Ver=1, Type=NON, TKL=0
    out[1] = 0x02; // Code=0.02 (POST)
    out[2..4].copy_from_slice(&message_id.to_be_bytes());
    out[4] = 0xFF; // payload marker
    out[5..5 + payload.len()].copy_from_slice(payload);
 
    Some(5 + payload.len())
}

pub enum ServerResponse {
    Ack,
    AuthSessionTimeout,
    Unknown,
}

pub fn parse_response(payload: &[u8]) -> ServerResponse {
    match payload {
        b"ACK" => ServerResponse::Ack,
        b"ERROR:auth_session_timeout" => ServerResponse::AuthSessionTimeout,
        _ => ServerResponse::Unknown,
    }
}

pub fn extract_coap_payload(packet: &[u8]) -> Option<&[u8]> {
    if packet.len() < 4 {
        return None;
    }
 
    let token_len = (packet[0] & 0x0F) as usize;
    let mut offset = 4 + token_len;
    if offset > packet.len() {
        return None;
    }
 
    loop {
        let byte = *packet.get(offset)?;
 
        if byte == 0xFF {
            return Some(&packet[offset + 1..]);
        }
 
        offset += 1;
 
        let mut delta = (byte >> 4) as usize;
        let mut length = (byte & 0x0F) as usize;
 
        if delta == 13 {
            delta = *packet.get(offset)? as usize + 13;
            offset += 1;
        } else if delta == 14 {
            let hi = *packet.get(offset)? as u16;
            let lo = *packet.get(offset + 1)? as u16;
            delta = u16::from_be_bytes([hi as u8, lo as u8]) as usize + 269;
            offset += 2;
        }
 
        if length == 13 {
            length = *packet.get(offset)? as usize + 13;
            offset += 1;
        } else if length == 14 {
            let hi = *packet.get(offset)? as u16;
            let lo = *packet.get(offset + 1)? as u16;
            length = u16::from_be_bytes([hi as u8, lo as u8]) as usize + 269;
            offset += 2;
        }
 
        offset = offset.checked_add(length)?;
        if offset > packet.len() {
            return None;
        }
 
        let _ = delta;
    }
}
 