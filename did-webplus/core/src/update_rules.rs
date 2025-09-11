use crate::{Error, Result};
use mbc::{B64UHash, B64UHashStr, B64UPubKey, B64UPubKeyStr};
use std::{cell::OnceCell, collections::HashMap, ops::Deref};

pub struct ValidProofData {
    key: B64UPubKey,
    #[allow(dead_code)]
    hashed_key_mc: OnceCell<HashMap<u64, B64UHash>>,
}

impl ValidProofData {
    pub fn from_key(key: B64UPubKey) -> Self {
        Self {
            key,
            hashed_key_mc: OnceCell::new(),
        }
    }
    // pub fn from_hashed_key(hashed_key: B64UHash) -> Self {
    //     let hashed_key_mc = OnceCell::new();
    //     let hashed_key_m = hashed_key_mc.get_mut().unwrap();
    //     let hash_codec = hashed_key.decoded().unwrap().codec();
    //     hashed_key_m.insert(hash_codec, hashed_key);
    //     Self {
    //         key: None,
    //         hashed_key_mc,
    //     }
    // }
    pub fn key(&self) -> &B64UPubKeyStr {
        self.key.deref()
    }
    pub fn hashed_key(&self, _hash_codec: u64) -> &B64UHashStr {
        todo!("ValidProofData::hashed_key");
        // if let Some(hashed_key_m) = self.hashed_key_mc.get() {
        //     if let Some(hashed_key) = hashed_key_m.get(&hash_codec) {
        //         // If we already have a hash for this codec, return it.
        //         return hashed_key;
        //     }
        // } else {
        //     // If hashed_key_mc isn't yet initialized, initialize it.
        //     self.hashed_key_mc.get_or_init(|| HashMap::new());
        // }
        // // We don't yet have a hash for this codec, so compute it from the key.
        // use selfhash::HashFunctionT;
        // let hasher = selfhash::B64UHashFunction::new(hash_codec)
        //     .expect("programmer error")
        //     .new_hasher();
        // hasher.update(key.as_bytes());
        // let hash = hasher.finalize();
        // let hashed_key_m = self.hashed_key_mc.get_mut().unwrap();
        // hashed_key_m.insert(hash_codec, hash);
        // hashed_key_m.get(&hash_codec).unwrap()
    }
}

pub trait VerifyRules {
    fn verify_rules(&self, valid_proof_data_v: &[ValidProofData]) -> Result<()>;
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct UpdatesDisallowed {}

impl VerifyRules for UpdatesDisallowed {
    fn verify_rules(&self, _valid_proof_key_v: &[ValidProofData]) -> Result<()> {
        Err(Error::InvalidDIDUpdateOperation("UpdatesDisallowed"))
    }
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct UpdateKey {
    pub key: B64UPubKey,
}

impl VerifyRules for UpdateKey {
    fn verify_rules(&self, valid_proof_data_v: &[ValidProofData]) -> Result<()> {
        for valid_proof_key in valid_proof_data_v.iter() {
            if valid_proof_key.key() == self.key.deref() {
                return Ok(());
            }
        }
        // TODO: Give details about which rules failed.  This potentially affects the UX.
        Err(Error::InvalidDIDUpdateOperation("Key"))
    }
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct HashedUpdateKey {
    #[serde(rename = "hashedKey")]
    pub hashed_key: B64UHash,
}

impl VerifyRules for HashedUpdateKey {
    fn verify_rules(&self, valid_proof_data_v: &[ValidProofData]) -> Result<()> {
        let hash_codec = self.hashed_key.decoded().unwrap().codec();
        for valid_proof_key in valid_proof_data_v.iter() {
            if valid_proof_key.hashed_key(hash_codec) == self.hashed_key.deref() {
                return Ok(());
            }
        }
        // TODO: Give details about which rules failed.  This potentially affects the UX.
        Err(Error::InvalidDIDUpdateOperation("HashedKey"))
    }
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct Any {
    pub any: Vec<UpdateRules>,
}

impl VerifyRules for Any {
    fn verify_rules(&self, valid_proof_data_v: &[ValidProofData]) -> Result<()> {
        // Simple recursive definition.
        for update_rules in self.any.iter() {
            if update_rules.verify_rules(valid_proof_data_v).is_ok() {
                return Ok(());
            }
        }
        // TODO: Give details about which rules failed.  This potentially affects the UX.
        Err(Error::InvalidDIDUpdateOperation("Any"))
    }
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct All {
    all: Vec<UpdateRules>,
}

impl All {
    pub fn new(all: Vec<UpdateRules>) -> Self {
        if all.is_empty() {
            panic!("`All`-typed update rules must be non-empty");
        }
        Self { all }
    }
}

impl VerifyRules for All {
    fn verify_rules(&self, valid_proof_data_v: &[ValidProofData]) -> Result<()> {
        // Simple recursive definition.
        for update_rules in self.all.iter() {
            if let Err(e) = update_rules.verify_rules(valid_proof_data_v) {
                return Err(e);
            }
        }
        // If all subordinate rules verified, then this rule is defined to be verified.
        Ok(())
    }
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct WeightedUpdateRules {
    #[serde(default = "one", skip_serializing_if = "is_one")]
    weight: u32,
    #[serde(flatten)]
    update_rules: UpdateRules,
}

impl WeightedUpdateRules {
    pub fn new(weight: u32, update_rules: UpdateRules) -> Self {
        if weight == 0 {
            panic!("WeightedUpdateRules weight must be greater than 0");
        }
        Self {
            weight,
            update_rules,
        }
    }
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct Threshold {
    #[serde(rename = "atLeast")]
    at_least: u32,
    of: Vec<WeightedUpdateRules>,
}

impl Threshold {
    pub fn new(at_least: u32, of: Vec<WeightedUpdateRules>) -> Self {
        if at_least == 0 {
            panic!("Threshold at_least must be greater than 0");
        }
        if of.is_empty() {
            panic!("Threshold of must be non-empty");
        }
        let max_weight_sum = of.iter().map(|w| w.weight).sum::<u32>();
        if at_least > max_weight_sum {
            panic!("Threshold at_least must be less than or equal to the sum of the weights of the of rules");
        }
        Self { at_least, of }
    }
}

impl VerifyRules for Threshold {
    fn verify_rules(&self, valid_proof_data_v: &[ValidProofData]) -> Result<()> {
        let mut weight_sum = 0;
        for weighted_update_rules in self.of.iter() {
            if weighted_update_rules
                .update_rules
                .verify_rules(valid_proof_data_v)
                .is_ok()
            {
                weight_sum += weighted_update_rules.weight;
            }
        }
        if weight_sum >= self.at_least {
            Ok(())
        } else {
            // TODO: Give details about which rules failed.  This potentially affects the UX.
            Err(Error::InvalidDIDUpdateOperation("Threshold"))
        }
    }
}

/// Helper function for serde deserialization.
const fn one() -> u32 {
    1
}

/// Helper function for serde deserialization.
const fn is_one(n: &u32) -> bool {
    *n == 1
}

/// Uses default weight of 1.
impl<T: Into<UpdateRules>> From<T> for WeightedUpdateRules {
    fn from(t: T) -> Self {
        let weight = 1;
        let update_rules = t.into();
        WeightedUpdateRules {
            weight,
            update_rules,
        }
    }
}

/// This type doesn't include the UpdatesDisallowed variant, because that one may only be used at the root level.
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(untagged)]
pub enum UpdateRules {
    Key(UpdateKey),
    HashedKey(HashedUpdateKey),
    Any(Any),
    All(All),
    Threshold(Threshold),
}

impl From<UpdateKey> for UpdateRules {
    fn from(key: UpdateKey) -> Self {
        UpdateRules::Key(key)
    }
}

impl From<HashedUpdateKey> for UpdateRules {
    fn from(hashed_key: HashedUpdateKey) -> Self {
        UpdateRules::HashedKey(hashed_key)
    }
}

impl From<Any> for UpdateRules {
    fn from(any: Any) -> Self {
        UpdateRules::Any(any)
    }
}

impl From<All> for UpdateRules {
    fn from(all: All) -> Self {
        UpdateRules::All(all)
    }
}

impl From<Threshold> for UpdateRules {
    fn from(threshold: Threshold) -> Self {
        UpdateRules::Threshold(threshold)
    }
}

impl VerifyRules for UpdateRules {
    fn verify_rules(&self, valid_proof_data_v: &[ValidProofData]) -> Result<()> {
        match self {
            UpdateRules::Key(key) => key.verify_rules(valid_proof_data_v),
            UpdateRules::HashedKey(hashed_key) => hashed_key.verify_rules(valid_proof_data_v),
            UpdateRules::Any(any) => any.verify_rules(valid_proof_data_v),
            UpdateRules::All(all) => all.verify_rules(valid_proof_data_v),
            UpdateRules::Threshold(threshold) => threshold.verify_rules(valid_proof_data_v),
        }
    }
}

/// Defines the update rules for a DID document.  Note that if the value is UpdatesDisallowed,
/// then no updates to the DID are allowed, meaning that the DID is "tombstoned".
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(untagged)]
pub enum RootLevelUpdateRules {
    UpdatesDisallowed(UpdatesDisallowed),
    UpdateRules(UpdateRules),
}

impl From<UpdatesDisallowed> for RootLevelUpdateRules {
    fn from(updates_disallowed: UpdatesDisallowed) -> Self {
        RootLevelUpdateRules::UpdatesDisallowed(updates_disallowed)
    }
}

impl<T: Into<UpdateRules>> From<T> for RootLevelUpdateRules {
    fn from(t: T) -> Self {
        let update_rules = t.into();
        RootLevelUpdateRules::UpdateRules(update_rules)
    }
}

impl VerifyRules for RootLevelUpdateRules {
    fn verify_rules(&self, valid_proof_data_v: &[ValidProofData]) -> Result<()> {
        match self {
            RootLevelUpdateRules::UpdatesDisallowed(updates_disallowed) => {
                updates_disallowed.verify_rules(valid_proof_data_v)
            }
            RootLevelUpdateRules::UpdateRules(update_rules) => {
                update_rules.verify_rules(valid_proof_data_v)
            }
        }
    }
}
