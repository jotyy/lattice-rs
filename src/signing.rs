use elliptic_curve::sec1::ToEncodedPoint;
use k256::{
  ecdsa::{recoverable::Signature, signature::Signer, SigningKey},
  PublicKey,
};
use libsm::{
  sm2::{ecc::EccCtx, signature::SigCtx},
  sm3::hash::Sm3Hash,
};
use num_bigint::BigUint;
use once_cell::sync::Lazy;
use rand_core::OsRng;
use sha256::digest_bytes;

// Cryptography types.
#[derive(Debug, Clone, Copy)]
pub enum Cryptography {
  NIST,
  GM,
}

// Error during signing.
#[derive(Debug, derive_more::Display, PartialEq, Clone)]
pub enum SigningError {
  #[display(fmt = "Message has to be a non-zero 32-bytes slice")]
  InvalidMessage,
}
impl std::error::Error for SigningError {}

#[derive(Debug, derive_more::Display, PartialEq, Clone)]
pub enum AddressErr {
  #[display(fmt = "Address check failed")]
  InvalidAddress,
}
impl std::error::Error for AddressErr {}

#[derive(Debug)]
pub struct KeyPair {
  pub pk: Vec<u8>,
  pub sk: BigUint,
  pub crypto: Cryptography,
}

static CONTEXT_GM: Lazy<SigCtx> = Lazy::new(SigCtx::new);
static CURVE_GM: Lazy<EccCtx> = Lazy::new(EccCtx::new);

impl KeyPair {
  pub fn new_keypair(crypto: Cryptography) -> KeyPair {
    match crypto {
      Cryptography::NIST => {
        let signing_key = SigningKey::random(&mut OsRng);
        KeyPair {
          pk: signing_key.verifying_key().to_bytes().to_vec(),
          sk: BigUint::from_bytes_be(&signing_key.to_bytes().to_vec()),
          crypto,
        }
      }
      Cryptography::GM => {
        let (pk, sk) = CONTEXT_GM.new_keypair();

        KeyPair {
          pk: CURVE_GM.point_to_bytes(&pk, false),
          sk,
          crypto,
        }
      }
    }
  }

  pub fn from_secret_key(bytes: &[u8], crypto: Cryptography) -> KeyPair {
    match crypto {
      Cryptography::NIST => {
        let signing_key = SigningKey::from_bytes(bytes).unwrap();
        let pk = PublicKey::from(&signing_key.verifying_key());
        let pk = pk.to_encoded_point(false);
        let pk = pk.as_bytes();

        KeyPair {
          pk: pk.to_vec(),
          sk: BigUint::from_bytes_be(bytes),
          crypto,
        }
      }
      Cryptography::GM => {
        let sk = BigUint::from_bytes_be(bytes);
        let pk = CONTEXT_GM.pk_from_sk(&sk);

        KeyPair {
          pk: CURVE_GM.point_to_bytes(&pk, false),
          sk,
          crypto,
        }
      }
    }
  }

  pub fn sign(&self, data: &[u8]) -> String {
    match self.crypto {
      Cryptography::NIST => {
        let signing_key = SigningKey::from_bytes(&self.sk.to_bytes_be()).unwrap();
        let signature: Signature = signing_key.sign(data);

        format!(
          "0x{}{}0{}",
          hex::encode(signature.r().to_bytes()),
          hex::encode(signature.s().to_bytes()),
          BigUint::from(u8::from(signature.recovery_id())).to_str_radix(16),
        )
      }
      Cryptography::GM => {
        let pk = CURVE_GM.bytes_to_point(&self.pk).unwrap();
        // Get the value "e"
        let e = CONTEXT_GM.hash("1234567812345678", &pk, data);
        let rs = CONTEXT_GM.sign_raw(&e, &self.sk);
        format!(
          "0x{}{}01{}",
          rs.get_r().to_str_radix(16),
          rs.get_s().to_str_radix(16),
          hex::encode(e),
        )
      }
    }
  }

  pub fn verify(&self, data: &[u8], signature: &str) -> bool {
    match self.crypto {
      Cryptography::NIST => {
        // let signature = hex::decode(signature).unwrap();
        // let mut bytes = [0u8; 65];
        // bytes[..65].copy_from_slice(&signature);

        // let signature = Signature::new();
        // let signing_key = SigningKey::from_bytes(&self.sk.to_bytes_be()).unwrap();
        // let verifying_key = VerifyingKey::from(&signing_key);

        // verifying_key.verify(data, &signature).is_ok()
        true
      }
      Cryptography::GM => {
        let signature = hex::decode(signature).unwrap();
        let pk = CURVE_GM.bytes_to_point(&self.pk).unwrap();
        let signature =
          libsm::sm2::signature::Signature::new(&signature[0..32], &signature[32..64]);

        CONTEXT_GM.verify(data, &pk, &signature)
      }
    }
  }

  pub fn address(&self) -> String {
    let key_encode = &hex::encode(&self.pk)[2..];
    let key_decode = hex::decode(key_encode).unwrap();
    public_to_address(&key_decode, self.crypto)
  }
}

pub fn public_to_address(pk: &[u8], crypto: Cryptography) -> String {
  let key_hash = hash_message(pk, crypto);
  let eth = &hex::decode(key_hash.as_bytes()).unwrap()[12..];
  eth_to_lattice(eth)
}

pub fn eth_to_lattice(eth: &[u8]) -> String {
  let prefix = hex::decode("01").unwrap();
  let hash = [&prefix, eth].concat();
  let d1 = hex::decode(digest_bytes(&hash)).unwrap();
  let d2 = hex::decode(digest_bytes(&d1)).unwrap();
  let d3 = [&prefix, eth, &d2[0..4]].concat();
  let encoded = bs58::encode(d3).into_string();
  format!("zltc_{}", encoded)
}

pub fn lattice_to_eth(address: &str) -> String {
  let addr = &address[5..];
  let decoded = bs58::decode(addr).into_vec().unwrap();
  let len = decoded.len() - 4;

  let data = &decoded[1..len];
  hex::encode(data)
}

pub trait Key {
  fn sign(
    &self,
    message: &[u8],
    lattice_id: Option<u64>,
    crypto: Cryptography,
  ) -> Result<&str, SigningError>;

  fn sign_message(&self, message: &[u8], crypto: Cryptography) -> Result<&str, SigningError>;

  fn address(&self) -> &str;
}

pub fn hash_message(bytes: &[u8], crypto: Cryptography) -> String {
  match crypto {
    Cryptography::NIST => digest_bytes(bytes),
    Cryptography::GM => {
      let mut hash = Sm3Hash::new(bytes);
      let digest = hash.get_hash().to_vec();
      hex::encode(digest)
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn gen_key_pair() {
    let key_pair_nist = KeyPair::new_keypair(Cryptography::NIST);
    let key_pair_gm = KeyPair::new_keypair(Cryptography::GM);

    assert_eq!(key_pair_nist.pk.len(), 65);
    assert_eq!(key_pair_gm.pk.len(), 65);
    assert_eq!(key_pair_nist.sk.to_str_radix(16).len(), 64);
    assert_eq!(key_pair_gm.sk.to_str_radix(16).len(), 64);
  }

  #[test]
  fn from_nist_secret_key() {
    let sk_nist =
      hex::decode("197e504e9db094b588bfbd49d0a4277c3564d1e4e924ec5812294a7a94b012d7").unwrap();
    let expected_pk = "04749c609926d883afd444ced3b0b260cacd1b5280f3345f9b55d037f6964f9b76b89159ee902f2a4a44979054b1176449ad03c0e080764b3ca8bd7b5e401122d1";
    let key_pair_nist = KeyPair::from_secret_key(&sk_nist, Cryptography::NIST);
    let pk = hex::encode(key_pair_nist.pk);
    assert_eq!(pk, expected_pk);
  }

  #[test]
  fn from_gm_secret_key() {
    let sk_gm =
      hex::decode("197e504e9db094b588bfbd49d0a4277c3564d1e4e924ec5812294a7a94b012d7").unwrap();
    let expect_pk = hex::decode("041ab529cf433901a16ada0f40a2f558d1db179b181c2bb46b69565b052ad8ecb6e3c6df54eeafe56ddfa64a149896df5d9e6d19ba38f65405c803833f1d3c4cbf").unwrap();

    let key_pair_gm = KeyPair::from_secret_key(&sk_gm, Cryptography::GM);
    assert_eq!(key_pair_gm.pk, expect_pk);
  }

  #[test]
  fn sign_nist() {
    let sk =
      hex::decode("c842e1ef9ece7e992a4021423a58d6e89c751881e43fd7dbebe70f932ad493e2").unwrap();

    let data =
      hex::decode("790dcb1e43ac151998f8c2e59e0959072f9d476d19fb6f98d7a4e59ea5f8e59e").unwrap();

    let key_pair = KeyPair::from_secret_key(&sk, Cryptography::NIST);

    let sig = KeyPair::sign(&key_pair, &data);
    assert_eq!(sig, "0xc8eced818b011433b5d486f9f0c97c8d0180a0df042bcaf1e75a7cd20d66920a5bbc4901bd90353fc62828ed2a821a801440f294779fc402033bf92c7657c30600");
  }

  // #[test]
  // fn sign_gm() {
  //     let key_pair = KeyPair::new_keypair(Cryptography::GM);

  //     let sig = KeyPair::sign(&key_pair, &[0xab; 32]);

  //     assert_eq!(sig.len(), 194);
  // }

  #[test]
  fn hash_message_nist() {
    let expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    let actual = hash_message(b"hello", Cryptography::NIST);
    assert_eq!(actual, expected);
  }

  #[test]
  fn hash_message_gm() {
    let expected = "becbbfaae6548b8bf0cfcad5a27183cd1be6093b1cceccc303d9c61d0a645268";
    let actual = hash_message(b"hello", Cryptography::GM);
    assert_eq!(actual, expected);
  }

  #[test]
  fn public_to_address_nist() {
    let pk = hex::decode("749c609926d883afd444ced3b0b260cacd1b5280f3345f9b55d037f6964f9b76b89159ee902f2a4a44979054b1176449ad03c0e080764b3ca8bd7b5e401122d1").unwrap();
    let expect = "zltc_bg3H1ZjshPeQ6wxumDWApVJPWRRc7LCgD";

    let address = public_to_address(&pk, Cryptography::NIST);

    assert_eq!(address, expect)
  }

  #[test]
  fn lattice_to_eth_address() {
    let lattice = "zltc_bg3H1ZjshPeQ6wxumDWApVJPWRRc7LCgD";
    let eth = lattice_to_eth(lattice);

    assert_eq!(eth, "7c56662ae9431a43ebe154b1597ea6845bab4bab");
  }
}
