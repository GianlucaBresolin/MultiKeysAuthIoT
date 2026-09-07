use crate::crypto;
use heapless::Vec;
use rand_core::Rng;

const SKEY_LEN: usize = 32;
const KEY_LEN: usize = 32;
const IV_LEN: usize = 16;
const MAX_KEYS: usize = 1024;
const PLAINTEXT_BUF_LEN: usize = MAX_KEYS * KEY_LEN;

const fn encrypted_buf_len(plaintext_len: usize) -> usize {
    let padded_len = (plaintext_len / 16 + 1) * 16;
    IV_LEN + padded_len
}

const CIPHERTEXT_BUF_LEN: usize = encrypted_buf_len(PLAINTEXT_BUF_LEN);

#[derive(Debug)]
pub enum Error {
    TooManyKeys,
    NotInitialized,
}

pub struct DeviceKeyStore<R: Rng> {
    skey: [u8; SKEY_LEN],
    rng: R,
    ciphertext: Vec<u8, CIPHERTEXT_BUF_LEN>,
    key_count: usize,
}

impl<R: Rng> DeviceKeyStore<R> {
    pub fn init(skey: [u8; SKEY_LEN], rng: R) -> Self {
        Self {
            skey,
            rng,
            ciphertext: Vec::new(),
            key_count: 0,
        }
    }

    pub fn store_keys(
        &mut self,
        keys: &[[u8; KEY_LEN]],
        key_count: usize,
    ) -> Result<(), Error> {
        if key_count > MAX_KEYS {
            return Err(Error::TooManyKeys);
        }

        let mut plaintext: Vec<u8, PLAINTEXT_BUF_LEN> = Vec::new();

        for i in 0..key_count {
            for b in keys[i].iter() {
                plaintext.push(*b).map_err(|_| Error::TooManyKeys)?;
            }
        }

        let mut out_buf = [0u8; CIPHERTEXT_BUF_LEN];
        let n = crypto::encrypt_aes_cbc(&mut self.rng, &self.skey, &plaintext, &mut out_buf);

        self.ciphertext.clear();
        self.ciphertext
            .extend_from_slice(&out_buf[..n])
            .map_err(|_| Error::TooManyKeys)?;

        self.key_count = key_count;

        Ok(())
    }

    pub fn get_keys(&self) -> Result<Vec<[u8; KEY_LEN], MAX_KEYS>, Error> {
        if self.ciphertext.is_empty() {
            return Err(Error::NotInitialized);
        }

        let mut plaintext_buf = [0u8; PLAINTEXT_BUF_LEN];
        let plaintext =
            crypto::decrypt_aes_cbc(&self.skey, &self.ciphertext, &mut plaintext_buf);

        let mut keys: Vec<[u8; KEY_LEN], MAX_KEYS> = Vec::new();

        for i in 0..self.key_count {
            let mut key = [0u8; KEY_LEN];
            key.copy_from_slice(&plaintext[i * KEY_LEN..(i + 1) * KEY_LEN]);
            keys.push(key).map_err(|_| Error::TooManyKeys)?;
        }

        Ok(keys)
    }
}