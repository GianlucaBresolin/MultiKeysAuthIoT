use aes::Aes256;
use cbc::{Decryptor, Encryptor};
use cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use rand_core::Rng;
use sha2::Sha256;

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;
type HmacSha256 = Hmac<Sha256>;

const IV_LEN: usize = 16;

pub fn hmac(data: &[u8], key: &[u8], out: &mut [u8; 32]) {
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(data);
    out.copy_from_slice(&mac.finalize().into_bytes());
}

pub fn encrypt_aes_cbc<R: Rng>(
    rng: &mut R,
    key: &[u8; 32],
    plaintext: &[u8],
    out: &mut [u8],
) -> usize {
    let (iv, rest) = out.split_at_mut(IV_LEN);
    rng.fill_bytes(iv);

    let cipher = Aes256CbcEnc::new_from_slices(key, iv).unwrap();
    let ciphertext = cipher
        .encrypt_padded_b2b_mut::<Pkcs7>(plaintext, rest)
        .unwrap();

    IV_LEN + ciphertext.len()
}

pub fn decrypt_aes_cbc<'a>(key: &[u8; 32], data: &[u8], out: &'a mut [u8]) -> &'a [u8] {
    let (iv, ciphertext) = data.split_at(IV_LEN);
    let cipher = Aes256CbcDec::new_from_slices(key, iv).unwrap();
    cipher
        .decrypt_padded_b2b_mut::<Pkcs7>(ciphertext, out)
        .unwrap()
}