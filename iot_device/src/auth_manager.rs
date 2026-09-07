use alloc::vec::Vec;
use heapless::Vec as HVec;
use rand_core::Rng;

use smoltcp::iface::Interface;
use smoltcp::time::Instant;

use crate::communication_manager::CommunicationManager;
use crate::secure_store::DeviceKeyStore;
use crate::crypto;
use crate::uart;

const AES_IV_AND_PAD_BUF: usize = 256;

pub struct AuthManager<'a, R>
where
    R: Rng,
{
    key_store: &'a DeviceKeyStore,
    rng: R,
    comm: CommunicationManager<'a>,
    iot_uid: u8,
    p: u8,
    t1: Option<u64>,
    r2: Option<[u8; 8]>,
    session_key: Option<[u8; 32]>,
    coap_buf: [u8; 256],
    coap_len: usize,
    message_id: u16,
    last_c2: HVec<u8, 64>,
}

impl<'a, R> AuthManager<'a, R>
where
    R: Rng,
{
    pub fn new(
        key_store: &'a DeviceKeyStore,
        rng: R,
        comm: CommunicationManager<'a>,
        iot_uid: u8,
        p: u8,
    ) -> Self {
        Self {
            key_store,
            rng,
            comm,
            iot_uid,
            p,
            t1: None,
            r2: None,
            session_key: None,
            coap_buf: [0u8; 256],
            coap_len: 0,
            message_id: 0,
            last_c2: HVec::new(),
        }
    }

    pub fn init_auth_session(&mut self) {
        // M1 = {iot_uid}
        let m1 = [self.iot_uid];

        // send M1 (application payload only)
        if let Some(m2_payload) = self.comm.send_and_receive(&m1) {
            // handle M2 and prepare M3
            if let Some(m3_pkt) = self.process_m2_and_build_m3(&m2_payload) {
                // send M3
                if let Some(m4_payload) = self.comm.send_and_receive(&m3_pkt) {
                    // handle M4
                    self.process_m4(&m4_payload);
                } else {
                    uart::puts("AuthManager: no M4 received\r\n");
                }
            } else {
                uart::puts("AuthManager: failed to build M3\r\n");
            }
        } else {
            uart::puts("AuthManager: no M2 received\r\n");
        }
    }

    fn process_m2_and_build_m3(&mut self, m2: &[u8]) -> Option<Vec<u8>> {
        // M2 format assumed: C1 (p bytes of indexes) || r1 (8 bytes)
        let expected_c1_len = self.p as usize;
        if m2.len() < expected_c1_len + 8 {
            uart::puts("AuthManager: M2 too short or malformed\r\n");
            return None;
        }

        let c1 = &m2[..expected_c1_len];
        let mut r1 = [0u8; 8];
        r1.copy_from_slice(&m2[expected_c1_len..expected_c1_len + 8]);

        // compute K1 by xor of keys selected by indices in C1
        let keys = match self.key_store.get_keys() {
            Ok(k) => k,
            Err(_) => {
                uart::puts("AuthManager: failed to read keys from keystore\r\n");
                return None;
            }
        };
        if keys.len() == 0 {
            uart::puts("AuthManager: no keys available\r\n");
            return None;
        }

        let mut k1 = [0u8; 32];
        for &idx in c1.iter() {
            let i = idx as usize;
            if i >= keys.len() {
                uart::puts("AuthManager: C1 index out of range\r\n");
                return None;
            }
            let kb = &keys[i];
            for j in 0..32 {
                k1[j] ^= kb[j];
            }
        }

        // generate t1
        let mut t1_bytes = [0u8; 8];
        self.rng.fill_bytes(&mut t1_bytes);
        let t1 = u64::from_be_bytes(t1_bytes);
        self.t1 = Some(t1);

        // choose C2 (p unique random indices)
        let n = keys.len();
        self.last_c2.clear();
        // If p > n it's impossible to pick unique indices
        if (self.p as usize) > n {
            uart::puts("AuthManager: p is larger than number of keys; cannot select unique C2\r\n");
            return None;
        }
        while self.last_c2.len() < (self.p as usize) {
            let mut b = [0u8; 2];
            self.rng.fill_bytes(&mut b);
            let idx = (u16::from_be_bytes(b) as usize) % n;
            let idx_u8 = idx as u8;
            // ensure uniqueness
            let mut found = false;
            for &existing in self.last_c2.iter() {
                if existing == idx_u8 {
                    found = true;
                    break;
                }
            }
            if !found {
                self.last_c2.push(idx_u8).ok();
            }
        }

        // generate r2 and store it for later verification
        let mut r2_bytes = [0u8; 8];
        self.rng.fill_bytes(&mut r2_bytes);
        self.r2 = Some(r2_bytes);

        // plaintext = r1 || t1 || C2 || r2
        let mut plaintext: Vec<u8> = Vec::new();
        plaintext.extend_from_slice(&r1);
        plaintext.extend_from_slice(&t1_bytes);
        plaintext.extend_from_slice(&self.last_c2);
        plaintext.extend_from_slice(&r2_bytes);

        // encrypt with AES-CBC using k1
        let mut out_buf = [0u8; AES_IV_AND_PAD_BUF];
        let enc_len = crypto::encrypt_aes_cbc(&mut self.rng, &k1, &plaintext, &mut out_buf);

        // return ciphertext (IV || ciphertext) as raw payload for CommunicationManager to wrap into CoAP
        let mut payload = Vec::new();
        payload.extend_from_slice(&out_buf[..enc_len]);
        Some(payload)
    }

    fn process_m4(&mut self, m4: &[u8]) {
        // reconstruct K2 from local keys using last_c2
        let keys = match self.key_store.get_keys() {
            Ok(k) => k,
            Err(_) => {
                uart::puts("AuthManager: failed to read keys from keystore\r\n");
                return;
            }
        };
        if self.last_c2.is_empty() {
            uart::puts("AuthManager: no C2 recorded\r\n");
            return;
        }
        let mut k2 = [0u8; 32];
        for &idx in self.last_c2.iter() {
            let i = idx as usize;
            if i >= keys.len() {
                uart::puts("AuthManager: C2 index out of range\r\n");
                return;
            }
            let kb = &keys[i];
            for j in 0..32 {
                k2[j] ^= kb[j];
            }
        }

        let t1 = match self.t1 {
            Some(v) => v,
            None => {
                uart::puts("AuthManager: t1 missing\r\n");
                return;
            }
        };
        let t1_bytes = t1.to_be_bytes();
        let mut t1_exp = [0u8; 32];
        for i in 0..32 {
            t1_exp[i] = t1_bytes[i % 8];
        }
        let mut dec_key = [0u8; 32];
        for i in 0..32 {
            dec_key[i] = k2[i] ^ t1_exp[i];
        }

        let mut plain_buf = [0u8; AES_IV_AND_PAD_BUF];
        let plaintext = crypto::decrypt_aes_cbc(&dec_key, m4, &mut plain_buf);

        if plaintext.len() < 16 {
            uart::puts("AuthManager: decrypted M4 too short\r\n");
            return;
        }

        let mut r2_recv = [0u8; 8];
        r2_recv.copy_from_slice(&plaintext[..8]);
        let mut t2_b = [0u8; 8];
        t2_b.copy_from_slice(&plaintext[8..16]);

        // verify r2
        if let Some(stored_r2) = self.r2 {
            if stored_r2 != r2_recv {
                uart::puts("AuthManager: r2 mismatch\r\n");
                return;
            }
        } else {
            uart::puts("AuthManager: no stored r2 to verify against\r\n");
            return;
        }

        let t2 = u64::from_be_bytes(t2_b);
        // derive session key = t1 xor t2 expanded to 32 bytes
        let t2_exp = t2.to_be_bytes();
        let mut sess = [0u8; 32];
        for i in 0..32 {
            sess[i] = t1_bytes[i % 8] ^ t2_exp[i % 8];
        }
        self.session_key = Some(sess);
        uart::puts("AuthManager: session key established\r\n");
    }

    pub fn get_session_key(&self) -> Option<[u8; 32]> {
        self.session_key
    }

    ////////////////////////////////////////////////////////////////
    /// CommunicationManager wrapper methods 
    ////////////////////////////////////////////////////////////////
    pub fn poll<DeviceT>(&mut self, iface: &mut Interface, net: &mut DeviceT, timestamp: Instant)
    where
        DeviceT: smoltcp::phy::Device,
    {
        self.comm.poll(iface, net, timestamp);
    }

    pub fn can_send(&mut self) -> bool {
        self.comm.can_send()
    }

    pub fn send_telemetry(&mut self, payload: &[u8]) -> bool {
        self.comm.send_to_server(payload)
    }

    pub fn try_receive_parsed(&mut self) -> Option<crate::communication_manager::CommResponse> {
        self.comm.try_receive_parsed()
    }
}
