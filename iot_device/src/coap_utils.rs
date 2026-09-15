
pub fn build_coap_non_post(
    message_id: u16,
    uri_path_segments: &[&[u8]],
    payload: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let mut offset = 4;

    out[0] = 0x50; // Ver=1, Type=NON, TKL=0
    out[1] = 0x02; // Code=0.02 (POST)
    out[2..4].copy_from_slice(&message_id.to_be_bytes());

    let mut prev_option_number = 0u16;
    const URI_PATH_OPTION: u16 = 11;

    for segment in uri_path_segments {
        let delta = URI_PATH_OPTION - prev_option_number;
        prev_option_number = URI_PATH_OPTION;

        let seg_len = segment.len();

        if delta > 12 || seg_len > 12 {
            return None;
        }

        if offset >= out.len() {
            return None;
        }
        out[offset] = ((delta as u8) << 4) | (seg_len as u8);
        offset += 1;

        if offset + seg_len > out.len() {
            return None;
        }
        out[offset..offset + seg_len].copy_from_slice(segment);
        offset += seg_len;
    }

    if offset >= out.len() {
        return None;
    }
    out[offset] = 0xFF; // payload marker
    offset += 1;

    if offset + payload.len() > out.len() {
        return None;
    }
    out[offset..offset + payload.len()].copy_from_slice(payload);
    offset += payload.len();

    Some(offset)
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
 