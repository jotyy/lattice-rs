use std::ops::Shl;

use crate::signing::{hash_message, lattice_to_eth, Cryptography};

use num_bigint::BigUint;
use rlp::RlpStream;
use serde::{Deserialize, Serialize};

pub(crate) const NUM_TX_FIELDS: usize = 14;
const ZERO_HASH: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";
const ZERO_LATTICE_ADDRESS: &str = "zltc_QLbz7JHiBTspS962RLKV8GndWFwjA5K66";

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct TransactionRequest {
  /// Transaction type
  #[serde(rename = "type")]
  pub transaction_type: String,
  /// Index number
  #[serde(skip_serializing_if = "Option::is_none")]
  pub number: Option<u128>,
  /// Parent block hash
  #[serde(skip_serializing_if = "Option::is_none")]
  #[serde(rename = "parentHash")]
  pub parent_hash: Option<String>,
  /// Daemon block hash
  #[serde(skip_serializing_if = "Option::is_none")]
  #[serde(rename = "daemonHash")]
  pub daemon_hash: Option<String>,
  /// From address
  pub owner: String,
  /// To address
  pub linker: Option<String>,
  /// Transaction amount
  #[serde(skip_serializing_if = "Option::is_none")]
  pub amount: Option<u128>,
  /// Transaction joule cost
  #[serde(skip_serializing_if = "Option::is_none")]
  pub joule: Option<u128>,
  /// Access list
  pub hub: Option<Vec<String>>,
  /// Transaction type
  pub timestamp: u64,
  /// Code
  pub code: Option<String>,
  /// Payload
  pub payload: Option<String>,
}

impl TransactionRequest {
  /// Creates an empty transaction request with all fields left empty
  pub fn new() -> Self {
    Self::default()
  }

  pub fn encode(&self, chain_id: u32, crypto: Cryptography) -> (BigUint, Vec<u8>) {
    // let pow = self.pow(chain_id, crypto);
    let pow = BigUint::from(0 as u32);
    let stream = self.rlp(chain_id, hex::encode(&pow.to_bytes_be()), crypto, true);
    (pow, stream.out().to_vec())
  }

  pub fn pow(&self, chain_id: u32, crypto: Cryptography) -> BigUint {
    let mut i: u32 = 0;
    let min: BigUint = BigUint::from(1u32).shl(244);
    loop {
      i = i + 1;
      let pow = BigUint::from(i);
      let stream = self.rlp(chain_id, hex::encode(&pow.to_bytes_be()), crypto, false);
      let rlp = stream.out().to_vec();
      let hash = hash_message(&rlp, crypto);
      let bytes = hex::decode(hash).unwrap();
      let calculated = BigUint::from_bytes_be(&bytes);
      if calculated.le(&min) {
        return pow;
      }
    }
  }

  /// Gets the unsigned transactions RLP encoding
  pub fn rlp(&self, chain_id: u32, _pow: String, crypto: Cryptography, is_sign: bool) -> RlpStream {
    let mut rlp = RlpStream::new();
    rlp.begin_list(NUM_TX_FIELDS + if is_sign { 2 } else { 0 });

    let parent_hash = match &self.parent_hash {
      Some(value) => hex::decode(&value[2..]).unwrap(),
      None => "0".as_bytes().to_vec(),
    };
    let hub = match &self.hub {
      Some(value) => value.to_vec(),
      None => {
        let empty: Vec<String> = vec![];
        empty
      }
    };
    let hub_arr = hub
      .into_iter()
      .map(|e| hex::decode(&e[2..]).unwrap())
      .collect::<Vec<Vec<u8>>>();
    let daemon_hash = match &self.daemon_hash {
      Some(value) => hex::decode(&value[2..]).unwrap(),
      None => "0".as_bytes().to_vec(),
    };
    let owner_addr = hex::decode(lattice_to_eth(&self.owner)).unwrap();
    let linker_addr = match &self.linker {
      Some(value) => {
        let addr = lattice_to_eth(&value.to_owned());
        hex::decode(addr).unwrap()
      }
      None => hex::decode(lattice_to_eth(ZERO_LATTICE_ADDRESS)).unwrap(),
    };
    let code_hash = match &self.code {
      Some(value) => {
        let bytes = hex::decode(&value[2..]).unwrap();
        hash_message(&bytes, crypto)
      }
      None => ZERO_HASH[2..].to_string(),
    };
    let code = hex::decode(&code_hash).unwrap();
    let payload = match &self.payload {
      Some(value) => {
        if value == "" {
          hex::decode("").unwrap()
        } else {
          hex::decode(&value[2..]).unwrap()
        }
      }
      None => hex::decode("").unwrap(),
    };

    rlp.append(&opt_num_to_vec(self.number));
    rlp.append(&type_to_vec(&self.transaction_type));
    rlp.append(&parent_hash);
    rlp.append_list::<Vec<u8>, Vec<u8>>(&hub_arr);
    rlp.append(&daemon_hash);
    rlp.append(&code);
    rlp.append(&owner_addr);
    rlp.append(&linker_addr);
    rlp.append(&opt_num_to_vec(self.amount));
    rlp.append(&opt_num_to_vec(self.joule));
    // rlp.append(&hex::decode(pow).unwrap());
    rlp.append(&hex::decode("").unwrap());
    rlp.append(&hex::decode("").unwrap());
    rlp.append(&payload);
    rlp.append(&num_to_bytes(self.timestamp as u128));
    rlp.append(&num_to_bytes(chain_id as u128));
    if is_sign {
      rlp.append(&hex::decode("").unwrap());
      rlp.append(&hex::decode("").unwrap());
    }
    rlp
  }
}

fn type_to_vec(value: &str) -> Vec<u8> {
  let hex = match value {
    "genesis" => "00",
    "create" => "01",
    "send" => "02",
    "receive" => "03",
    "contract" => "04",
    "execute" => "05",
    "beacon" => "06",
    _ => "00",
  };
  hex::decode(hex).unwrap()
}

fn num_to_bytes(value: u128) -> Vec<u8> {
  BigUint::from(value).to_bytes_be()
}

fn opt_num_to_vec(value: Option<u128>) -> Vec<u8> {
  match value {
    Some(value) => {
      if value == 0 {
        hex::decode("").unwrap()
      } else {
        num_to_bytes(value)
      }
    }
    None => hex::decode("").unwrap(),
  }
}

#[cfg(test)]
mod tests {
  use rlp::RlpStream;

  use crate::{
    signing::{hash_message, Cryptography, KeyPair},
    types::transaction::TransactionRequest,
  };

  #[test]
  fn sign() {
    let sk =
      hex::decode("c842e1ef9ece7e992a4021423a58d6e89c751881e43fd7dbebe70f932ad493e2").unwrap();
    let tx_json = r#"
  {
    "type": "receive",
    "number": 1,
    "parentHash": "0x11fd058b3a58bf060ca8f0ef5066273b5c113179e78c17d420db79e2189ac9da",
    "daemonHash": "0xb9072e250545d3f1018d47f0c28edf1de065e4484ed3dc8f4e2f5e96175afdfc",
    "owner": "zltc_TJkicFdzg1eb6BAiJpWB8Pr89U4SSGa5j",
    "linker": "zltc_cmSPSxJPiwhLQkUBou5kWVubeMNwkBgJ3",
    "amount": 0,
    "joule": 0,
    "hub": [
        "0x48f51790c39369cd02997382170c01a5546d9e361b56386808a00be83b5ad5d6"
    ],
    "timestamp": 1644288854
  }
    "#;

    let transaction = serde_json::from_str::<TransactionRequest>(tx_json).unwrap();

    let pow = "01".to_string();
    let stream = transaction.rlp(1, pow, Cryptography::NIST, true);
    let encoded = stream.out().to_vec();
    let hash = hash_message(&encoded, Cryptography::NIST);

    assert_eq!(hex::encode(encoded), "f8bd0103a011fd058b3a58bf060ca8f0ef5066273b5c113179e78c17d420db79e2189ac9dae1a048f51790c39369cd02997382170c01a5546d9e361b56386808a00be83b5ad5d6a0b9072e250545d3f1018d47f0c28edf1de065e4484ed3dc8f4e2f5e96175afdfca0000000000000000000000000000000000000000000000000000000000000000094208ed5cccc047bee1d057972614fd032c30475cf948853e592e25e217e9a847f080806341518158dd980800180846201db56018080");

    assert_eq!(
      hash,
      "2f17153398a10a29e781791c534b0324817c5a2c8ffa81d9cf457647f4e65401"
    );

    let expect = "0x662ac591c5bca714e45afdb6275c888c6041977d36e7fa7992883215afad1344365ed20d5d4a4cbb0633aeb822ddd24cce2f8d43cb987a37b8963ad443e7efb801".to_string();

    let key_pair = KeyPair::from_secret_key(&sk, Cryptography::NIST);
    let sig = key_pair.sign(&hex::decode(&hash).unwrap());

    assert_eq!(sig, expect);
  }

  #[test]
  fn rlp() {
    let mut stream = RlpStream::new_list(1);
    let item =
      hex::decode(&"0x11fd058b3a58bf060ca8f0ef5066273b5c113179e78c17d420db79e2189ac9da"[2..])
        .unwrap();
    stream.append_list::<Vec<u8>, Vec<u8>>(&vec![item]);

    let item2 = hex::decode("").unwrap();
    let res = rlp::encode(&item2);

    println!("{}", hex::encode(&stream.out().to_vec()));
    println!("{}", hex::encode(res.to_vec()));
  }
}
