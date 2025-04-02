use openssl::symm::{Cipher, Crypter, Mode};
use serde::{Deserialize, Serialize};

pub(crate) const IV_LEN: usize = 16;
pub(crate) const KEY_LEN: usize = 32;

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct Key(pub [u8; KEY_LEN]);

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct IV(pub [u8; IV_LEN]);

impl IV {
    pub fn from_bytes(s: &[u8]) -> Self {
        let mut buf = [0u8; IV_LEN];

        let len = s.len().min(IV_LEN);
        buf[..len].copy_from_slice(&s[..len]);

        Self(buf)
    }
}

pub(crate) fn random_key() -> Key {
    let mut k = [0; KEY_LEN];
    rand::fill(&mut k[..]);
    Key(k)
}

pub(crate) fn decrypt(encrypted_data: &[u8], key: &Key, iv: &IV) -> Vec<u8> {
    let cipher = Cipher::aes_256_cbc();
    let mut decrypter = Crypter::new(cipher, Mode::Decrypt, &key.0, Some(&iv.0)).unwrap();

    let block_size = cipher.block_size();
    let mut decrypted_data = vec![0; encrypted_data.len() + block_size];
    let count = decrypter
        .update(encrypted_data, &mut decrypted_data)
        .unwrap();
    let rest = decrypter.finalize(&mut decrypted_data[count..]).unwrap();
    decrypted_data.truncate(count + rest);

    decrypted_data
}

pub(crate) fn encrypt(data: &[u8], key: &Key, iv: &IV) -> Vec<u8> {
    let cipher = Cipher::aes_256_cbc();
    let mut encrypter = Crypter::new(cipher, Mode::Encrypt, &key.0, Some(&iv.0)).unwrap();

    let block_size = cipher.block_size();
    let mut encrypted_data = vec![0; data.len() + block_size];
    let count = encrypter.update(data, &mut encrypted_data).unwrap();
    let rest = encrypter.finalize(&mut encrypted_data[count..]).unwrap();
    encrypted_data.truncate(count + rest);

    encrypted_data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_sanity() {
        let data = vec![1, 2, 3, 4];
        let key = Key([1; KEY_LEN]);
        let iv = IV::from_bytes("testpass".as_bytes());

        let encrypted = encrypt(&data, &key, &iv);
        assert_eq!(
            encrypted,
            vec![38, 18, 161, 119, 20, 132, 125, 92, 211, 96, 187, 79, 89, 52, 133, 49]
        );

        let decrypted = decrypt(&encrypted, &key, &iv);
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_encryption_length() {
        // encrypted length should be: ceil(16 * n) * 16
        let data = vec![6u8; 1020];
        let key = random_key();
        let iv = IV::from_bytes("testpass".as_bytes());

        let enc = encrypt(&data, &key, &iv);
        assert_eq!(enc.len(), 1024);
    }
}
