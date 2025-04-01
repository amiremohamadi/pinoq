use openssl::symm::{Cipher, Crypter, Mode};
use serde::{Deserialize, Serialize};

pub(crate) const IV_LEN: usize = 16;
pub(crate) const KEY_LEN: usize = 32;

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct Key(pub [u8; KEY_LEN]);

pub(crate) fn random_key() -> Key {
    let mut k = [0; KEY_LEN];
    rand::fill(&mut k[..]);
    Key(k)
}

pub(crate) fn decrypt(encrypted_data: &[u8], key: &Key, password: &str) -> Vec<u8> {
    let mut iv = password.as_bytes().to_vec();
    iv.resize(IV_LEN, 0);

    let cipher = Cipher::aes_256_cbc();
    let mut decrypter = Crypter::new(cipher, Mode::Decrypt, &key.0, Some(&iv)).unwrap();

    let block_size = cipher.block_size();
    let mut decrypted_data = vec![0; encrypted_data.len() + block_size];
    let count = decrypter
        .update(encrypted_data, &mut decrypted_data)
        .unwrap();
    let rest = decrypter.finalize(&mut decrypted_data[count..]).unwrap();
    decrypted_data.truncate(count + rest);

    decrypted_data
}

pub(crate) fn encrypt(data: &[u8], key: &Key, password: &str) -> Vec<u8> {
    let mut iv = password.as_bytes().to_vec();
    iv.resize(IV_LEN, 0);

    let cipher = Cipher::aes_256_cbc();
    let mut encrypter = Crypter::new(cipher, Mode::Encrypt, &key.0, Some(&iv)).unwrap();

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

        let encrypted = encrypt(&data, &key, "testpass");
        assert_eq!(
            encrypted,
            vec![38, 18, 161, 119, 20, 132, 125, 92, 211, 96, 187, 79, 89, 52, 133, 49]
        );

        let decrypted = decrypt(&encrypted, &key, "testpass");
        assert_eq!(decrypted, data);
    }
}
