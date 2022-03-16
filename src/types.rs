use crate::utils::{hash_message, keccak256, normalize_recovery_id};
use candid::CandidType;
use elliptic_curve::consts::U32;
use generic_array::GenericArray;
use hex::FromHexError;
use ic_cdk::export::candid::{Deserialize, Nat};
use k256::{
    ecdsa::{
        recoverable::{Id as RecoveryId, Signature as RecoverableSignature},
        Signature as K256Signature,
    },
    EncodedPoint as K256PublicKey,
};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use serde::Serialize;
use std::hash::Hash;
use std::str::FromStr;
use tiny_keccak::{Hasher, Keccak};

#[derive(Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq)]
pub struct Address(pub [u8; 20]);

impl Encodable for Address {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(1);
        s.append(&self.0.to_vec());
    }
}

impl Decodable for Address {
    fn decode(rlp: &Rlp<'_>) -> Result<Self, DecoderError> {
        let addr: Vec<u8> = rlp.val_at(0).unwrap();
        let addr:[u8;20] = addr.try_into().unwrap();
        Ok(Address(addr))
    }
}

impl ToString for Address {
    fn to_string(&self) -> String {
        hex::encode(self.0)
    }
}

impl FromStr for Address {
    type Err = FromHexError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Address(hex::decode(s)?.try_into().unwrap()))
    }
}

impl Address {
    pub fn to_stirng(&self) -> String {
        hex::encode(self.0)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct H256(pub [u8; 32]);

#[derive(Clone, Debug, PartialEq)]
pub enum RecoveryMessage {
    /// Message bytes
    Data(Vec<u8>),
    /// Message hash
    Hash(H256),
}

#[derive(CandidType, Debug, Deserialize, Clone)]
pub struct U256(pub [u64; 4]);

#[derive(CandidType, Debug, Deserialize, Clone)]
pub struct Signature {
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub v: u64,
}

impl Signature {
    pub fn recover<M>(&self, message: M) -> Result<Address, String>
    where
        M: Into<RecoveryMessage>,
    {
        let message = message.into();
        let message_hash = match message {
            RecoveryMessage::Data(ref message) => hash_message(message),
            RecoveryMessage::Hash(hash) => hash.0,
        };
        let (recoverable_sig, _recovery_id) = self.as_signature().unwrap();
        let verify_key = recoverable_sig
            .recover_verify_key_from_digest_bytes(message_hash.as_ref().into())
            .unwrap();

        let uncompressed_pub_key = K256PublicKey::from(&verify_key).decompress();
        if let Some(public_key) = uncompressed_pub_key {
            let public_key = public_key.as_bytes();
            let hash = keccak256(&public_key[1..]);
            Ok(Address(hash[12..].try_into().unwrap()))
        } else {
            Err("recovery failed".to_string())
        }
    }

    fn as_signature(&self) -> Result<(RecoverableSignature, RecoveryId), String> {
        let recovery_id = self.recovery_id().unwrap();
        let signature = {
            let gar: &GenericArray<u8, U32> = GenericArray::from_slice(&self.r);
            let gas: &GenericArray<u8, U32> = GenericArray::from_slice(&self.s);
            let sig = K256Signature::from_scalars(*gar, *gas).unwrap();
            RecoverableSignature::new(&sig, recovery_id).unwrap()
        };

        Ok((signature, recovery_id))
    }
    fn recovery_id(&self) -> Result<RecoveryId, ()> {
        let standard_v = normalize_recovery_id(self.v);
        Ok(RecoveryId::new(standard_v).unwrap())
    }
}
