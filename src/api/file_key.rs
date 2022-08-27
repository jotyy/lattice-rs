use aes::{
  cipher::{NewCipher, StreamCipher, StreamCipherSeek},
  Aes128Ctr,
};
use rand::Rng;
use scrypt::{
  password_hash::{PasswordHasher, SaltString},
  Params, Scrypt,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
  signing::{hash_message, Cryptography, KeyPair},
  types::errors::IncorrectPassword,
};

#[derive(Serialize, Deserialize, Debug)]
pub struct FileKey {
  pub uuid: String,
  pub address: String,
  pub cipher: Cipher,
  #[serde(rename = "isGM")]
  pub is_gm: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Cipher {
  pub aes: Aes,
  pub kdf: Kdf,
  #[serde(rename = "cipherText")]
  pub cipher_text: String,
  pub mac: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Aes {
  pub cipher: String,
  pub iv: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Kdf {
  pub kdf: String,
  #[serde(rename = "kdfParams")]
  pub kdf_params: KdfParams,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KdfParams {
  #[serde(rename = "DKLen")]
  pub dk_len: u32,
  pub n: u32,
  pub p: u32,
  pub r: u32,
  pub salt: String,
}

impl FileKey {
  pub fn from_secret_key(sk: &[u8], password: &[u8], crypto: Cryptography) -> FileKey {
    let key_pair = KeyPair::from_secret_key(sk, crypto);
    FileKey {
      uuid: Uuid::new_v4().to_string(),
      address: KeyPair::address(&key_pair),
      cipher: _gen_cipher(sk, password, crypto),
      is_gm: matches!(crypto, Cryptography::GM),
    }
  }

  pub fn as_key_pair(&self, password: &[u8]) -> Result<KeyPair, IncorrectPassword> {
    let crypto = if self.is_gm {
      Cryptography::GM
    } else {
      Cryptography::NIST
    };

    let key = scrypt_key(password, &self.cipher.kdf.kdf_params.salt);
    let aes_key = hex::decode(&key[0..32]).unwrap();
    let hash_key = hex::decode(&key[32..64]).unwrap();
    let mac = compute_mac(&hash_key, &self.cipher.cipher_text, crypto);
    let iv = hex::decode(&self.cipher.aes.iv).unwrap();
    if mac.eq(&self.cipher.mac) {
      let sk_str = aes_decrypt(&self.cipher.cipher_text, &aes_key, &iv);
      let sk = hex::decode(sk_str).unwrap();
      let key_pair = KeyPair::from_secret_key(&sk, crypto);
      Ok(key_pair)
    } else {
      Err(IncorrectPassword)
    }
  }
}

fn _gen_cipher(sk: &[u8], password: &[u8], crypto: Cryptography) -> Cipher {
  let salt_bytes = rand::thread_rng().gen::<[u8; 32]>();
  let salt = hex::encode(&salt_bytes);
  let iv_bytes = rand::thread_rng().gen::<[u8; 16]>();
  let iv = hex::encode(&iv_bytes);
  let key = scrypt_key(password, &salt);
  let aes_key = hex::decode(&key[0..32]).unwrap();
  let hash_key = hex::decode(&key[32..64]).unwrap();
  let cipher_text = aes_encrypt(&sk, &aes_key, &iv_bytes);
  let mac = compute_mac(&hash_key, &cipher_text, crypto);

  Cipher {
    aes: Aes {
      cipher: "aes-128-ctr".to_string(),
      iv,
    },
    kdf: Kdf {
      kdf: "scrypt".to_string(),
      kdf_params: KdfParams {
        dk_len: 32,
        n: 262144,
        p: 1,
        r: 8,
        salt,
      },
    },
    cipher_text,
    mac,
  }
}

fn scrypt_key(password: &[u8], salt: &str) -> String {
  let salt_bytes = hex::decode(salt).unwrap();
  let salt_str = SaltString::b64_encode(&salt_bytes).unwrap();
  let params = Params::new(18, 8, 1).unwrap();
  let password_hash = Scrypt
    .hash_password_customized(password, None, None, params, &salt_str)
    .unwrap();
  let scrypt_output = password_hash.hash.unwrap();
  hex::encode(scrypt_output.as_bytes())
}

fn aes_encrypt(sk: &[u8], key: &[u8], iv: &[u8]) -> String {
  let mut cipher = Aes128Ctr::new_from_slices(key, iv).unwrap();
  let mut buffer = sk.to_vec();
  cipher.apply_keystream(&mut buffer);
  hex::encode(buffer)
}

fn aes_decrypt(cipher_text: &str, key: &[u8], iv: &[u8]) -> String {
  let mut cipher = Aes128Ctr::new_from_slices(key, iv).unwrap();
  let mut buffer = hex::decode(cipher_text).unwrap();
  cipher.seek(0);
  cipher.apply_keystream(&mut buffer);
  hex::encode(buffer)
}

fn compute_mac(key: &[u8], cipher_text: &str, crypto: Cryptography) -> String {
  let cipher_bytes = hex::decode(cipher_text).unwrap();
  let data = [key, &cipher_bytes].concat();
  hash_message(&data, crypto)
}

#[cfg(test)]
mod tests {
  use super::*;
  #[test]
  fn file_key_serialize() {
    let file_key = r#"
    {"uuid":"71c40ad7-ed7b-4b89-8adb-40b828a3674d","address":"zltc_bg3H1ZjshPeQ6wxumDWApVJPWRRc7LCgD","cipher":{"aes":{"cipher":"aes-128-ctr","cipherText":"e2262a7b5e775892265c4feed6f464412b9c1425eb34a84259b7cd80a580366a","iv":"e9c93bed11709f071463ed82752ec5b9"},"kdf":{"kdf":"scrypt","kdfParams":{"DKLen":32,"n":262144,"p":1,"r":8,"salt":"071c3f968c7788ac01a7df73626999357704b419b7e42015b45fe40cd20c68a1"}},"cipherText":"e2262a7b5e775892265c4feed6f464412b9c1425eb34a84259b7cd80a580366a","mac":"a7ea4aee139a1bcd14f1f9ff3b71807d32ecf7b15201371d02538f543e75e04f"},"isGM":false}
    "#;

    let de = serde_json::from_str::<FileKey>(file_key).unwrap();

    let addr = "zltc_bg3H1ZjshPeQ6wxumDWApVJPWRRc7LCgD";
    let mac = "a7ea4aee139a1bcd14f1f9ff3b71807d32ecf7b15201371d02538f543e75e04f";

    assert_eq!(de.address, addr);
    assert_eq!(de.cipher.mac, mac);
  }

  #[test]
  fn file_key_from_secret_key() {
    let sk_nist =
      hex::decode("197e504e9db094b588bfbd49d0a4277c3564d1e4e924ec5812294a7a94b012d7").unwrap();
    let addr = "zltc_bg3H1ZjshPeQ6wxumDWApVJPWRRc7LCgD";

    let now = std::time::Instant::now();

    // Code block to measure.
    {
      FileKey::from_secret_key(&sk_nist, b"asdf1234", Cryptography::GM);
    }

    let elapsed = now.elapsed();
    println!("Elapsed: {:.2?}", elapsed);

    let file_key = FileKey::from_secret_key(&sk_nist, b"asdf1234", Cryptography::NIST);
    assert_eq!(file_key.address, addr);
  }

  #[test]
  fn file_key_to_key_pair() {
    let password = b"asdf1234";
    let file_key_json = r#"
    {"uuid":"71c40ad7-ed7b-4b89-8adb-40b828a3674d","address":"zltc_bg3H1ZjshPeQ6wxumDWApVJPWRRc7LCgD","cipher":{"aes":{"cipher":"aes-128-ctr","cipherText":"e2262a7b5e775892265c4feed6f464412b9c1425eb34a84259b7cd80a580366a","iv":"e9c93bed11709f071463ed82752ec5b9"},"kdf":{"kdf":"scrypt","kdfParams":{"DKLen":32,"n":262144,"p":1,"r":8,"salt":"071c3f968c7788ac01a7df73626999357704b419b7e42015b45fe40cd20c68a1"}},"cipherText":"e2262a7b5e775892265c4feed6f464412b9c1425eb34a84259b7cd80a580366a","mac":"a7ea4aee139a1bcd14f1f9ff3b71807d32ecf7b15201371d02538f543e75e04f"},"isGM":false}
        "#;

    let sk_nist =
      hex::decode("197e504e9db094b588bfbd49d0a4277c3564d1e4e924ec5812294a7a94b012d7").unwrap();

    let file_key = serde_json::from_str::<FileKey>(file_key_json).unwrap();

    let key_pair = FileKey::as_key_pair(&file_key, password).unwrap();

    assert_eq!(
      &key_pair.pk,
      &KeyPair::from_secret_key(&sk_nist, Cryptography::NIST).pk
    );
  }
}
