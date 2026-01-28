use crate::{Error, Result};
use mbx::{MBHash, MBHashStr, MBPubKey, MBPubKeyStr};
use selfhash::HashRefT;

#[derive(Clone, Debug)]
pub struct ValidProofData {
    pub_key: MBPubKey,
}

impl ValidProofData {
    pub fn from_pub_key(pub_key: MBPubKey) -> Self {
        Self { pub_key }
    }
    pub fn pub_key(&self) -> &MBPubKeyStr {
        self.pub_key.as_mb_pub_key_str()
    }
}

pub trait VerifyRulesT {
    /// Verifies the update rules against the given valid proof data.  Returns Ok(()) if the rules are verified,
    /// otherwise returns an error.
    fn verify_rules(&self, valid_proof_data_v: &[ValidProofData]) -> Result<()>;
    /// For each pub key that in pub_key_v that occurs in the update rules (including the case where
    /// the update rule is a hashed key equal to the hash of one of the given pub keys), adds the index
    /// of the pub key to matching_pub_key_index_v.
    fn find_matching_update_keys(
        &self,
        pub_key_v: &[&MBPubKey],
        matching_pub_key_index_v: &mut Vec<usize>,
    );
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct UpdatesDisallowed {}

impl VerifyRulesT for UpdatesDisallowed {
    fn verify_rules(&self, _valid_proof_key_v: &[ValidProofData]) -> Result<()> {
        Err(Error::InvalidDIDUpdateOperation(
            "`UpdatesDisallowed` update rule prevents updates regardless of any valid proof data"
                .into(),
        ))
    }
    fn find_matching_update_keys(
        &self,
        _pub_key_v: &[&MBPubKey],
        _matching_pub_key_index_v: &mut Vec<usize>,
    ) {
        // No keys match
    }
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct UpdateKey {
    #[serde(rename = "key")]
    pub pub_key: MBPubKey,
}

impl VerifyRulesT for UpdateKey {
    fn verify_rules(&self, valid_proof_data_v: &[ValidProofData]) -> Result<()> {
        for valid_proof_key in valid_proof_data_v.iter() {
            if valid_proof_key.pub_key() == self.pub_key.as_mb_pub_key_str() {
                return Ok(());
            }
        }
        Err(Error::InvalidDIDUpdateOperation(
            format!(
                "`Key` update rule {} failed to verify because key {} did not match that of any valid proof data",
                serde_json::to_string(self).unwrap(),
                self.pub_key
            )
            .into(),
        ))
    }
    fn find_matching_update_keys(
        &self,
        pub_key_v: &[&MBPubKey],
        matching_pub_key_index_v: &mut Vec<usize>,
    ) {
        for (i, &pub_key) in pub_key_v.iter().enumerate() {
            if pub_key == &self.pub_key {
                matching_pub_key_index_v.push(i);
            }
        }
    }
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct HashedUpdateKey {
    #[serde(rename = "hashedKey")]
    hashed_pub_key: MBHash,
}

impl HashedUpdateKey {
    pub fn from_pub_key(
        mb_hash_function: &selfhash::MBHashFunction,
        pub_key: &MBPubKeyStr,
    ) -> Self {
        let hashed_pub_key = mb_hash_function.hash(pub_key.as_bytes());
        Self { hashed_pub_key }
    }
    pub fn from_hashed_pub_key(hashed_pub_key: MBHash) -> Self {
        Self { hashed_pub_key }
    }
    pub fn hashed_pub_key(&self) -> &MBHashStr {
        self.hashed_pub_key.as_mb_hash_str()
    }
    pub fn is_hash_of_pub_key(&self, pub_key: &MBPubKeyStr) -> bool {
        let mb_hash_function = self.hashed_pub_key.hash_function();
        let hashed_pub_key = mb_hash_function.hash(pub_key.as_bytes());
        hashed_pub_key == self.hashed_pub_key
    }
}

impl VerifyRulesT for HashedUpdateKey {
    fn verify_rules(&self, valid_proof_data_v: &[ValidProofData]) -> Result<()> {
        for valid_proof_key in valid_proof_data_v.iter() {
            // If the hash of the valid proof key matches the hashed pub key, then the rule is verified.
            if self.is_hash_of_pub_key(valid_proof_key.pub_key()) {
                return Ok(());
            }
        }
        Err(Error::InvalidDIDUpdateOperation(
            format!(
                "`HashedKey` update rule {} failed to verify because hashed key {} did not match that of any valid proof data",
                serde_json::to_string(self).unwrap(),
                self.hashed_pub_key
            )
            .into(),
        ))
    }
    fn find_matching_update_keys(
        &self,
        pub_key_v: &[&MBPubKey],
        matching_pub_key_index_v: &mut Vec<usize>,
    ) {
        for (i, &pub_key) in pub_key_v.iter().enumerate() {
            // Hash the pub key using the same base and hash function as the hashed pub key.
            // NOTE: If there are a lot of HashedUpdateKey-s in the update rules, this
            // will be computing the hashes redundantly, so it could be optimized.
            let mb_hash_function = self.hashed_pub_key.hash_function();
            let hashed_pub_key = mb_hash_function.hash(pub_key.as_bytes());
            // Compare the result to the hashed pub key.
            if hashed_pub_key == self.hashed_pub_key {
                matching_pub_key_index_v.push(i);
            }
        }
    }
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct Any {
    pub any: Vec<UpdateRules>,
}

impl VerifyRulesT for Any {
    fn verify_rules(&self, valid_proof_data_v: &[ValidProofData]) -> Result<()> {
        // Simple recursive definition.
        for update_rules in self.any.iter() {
            if update_rules.verify_rules(valid_proof_data_v).is_ok() {
                return Ok(());
            }
        }
        Err(Error::InvalidDIDUpdateOperation(
            format!(
                "`Any` update rule {} failed to verify",
                serde_json::to_string(self).unwrap()
            )
            .into(),
        ))
    }
    fn find_matching_update_keys(
        &self,
        pub_key_v: &[&MBPubKey],
        matching_pub_key_index_v: &mut Vec<usize>,
    ) {
        for update_rules in self.any.iter() {
            update_rules.find_matching_update_keys(pub_key_v, matching_pub_key_index_v);
        }
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

impl VerifyRulesT for All {
    fn verify_rules(&self, valid_proof_data_v: &[ValidProofData]) -> Result<()> {
        // Simple recursive definition.
        for update_rules in self.all.iter() {
            if let Err(e) = update_rules.verify_rules(valid_proof_data_v) {
                return Err(Error::InvalidDIDUpdateOperation(
                    format!(
                        "`All` update rule {} failed because subordinate rule failed: {}",
                        serde_json::to_string(self).unwrap(),
                        e
                    )
                    .into(),
                ));
            }
        }
        // If all subordinate rules verified, then this rule is defined to be verified.
        Ok(())
    }
    fn find_matching_update_keys(
        &self,
        pub_key_v: &[&MBPubKey],
        matching_pub_key_index_v: &mut Vec<usize>,
    ) {
        for update_rules in self.all.iter() {
            update_rules.find_matching_update_keys(pub_key_v, matching_pub_key_index_v);
        }
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
            // TODO: This should return an error because it depends on runtime data.
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
            // TODO: This should return an error because it depends on runtime data.
            panic!("Threshold at_least must be greater than 0");
        }
        if of.is_empty() {
            // TODO: This should return an error because it depends on runtime data.
            panic!("Threshold of must be non-empty");
        }
        let max_weight_sum = of.iter().map(|w| w.weight).sum::<u32>();
        if at_least > max_weight_sum {
            panic!(
                // TODO: This should return an error because it depends on runtime data.
                "Threshold at_least must be less than or equal to the sum of the weights of the of rules"
            );
        }
        Self { at_least, of }
    }
}

impl VerifyRulesT for Threshold {
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
            Err(Error::InvalidDIDUpdateOperation(
                format!(
                    "`Threshold` update rule {} failed to verify because weight sum ({}) was less than at_least ({})",
                    serde_json::to_string(self).unwrap(),
                    weight_sum,
                    self.at_least
                )
                .into(),
            ))
        }
    }
    fn find_matching_update_keys(
        &self,
        pub_key_v: &[&MBPubKey],
        matching_pub_key_index_v: &mut Vec<usize>,
    ) {
        for weighted_update_rules in self.of.iter() {
            weighted_update_rules
                .update_rules
                .find_matching_update_keys(pub_key_v, matching_pub_key_index_v);
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

impl VerifyRulesT for UpdateRules {
    fn verify_rules(&self, valid_proof_data_v: &[ValidProofData]) -> Result<()> {
        match self {
            UpdateRules::Key(key) => key.verify_rules(valid_proof_data_v),
            UpdateRules::HashedKey(hashed_key) => hashed_key.verify_rules(valid_proof_data_v),
            UpdateRules::Any(any) => any.verify_rules(valid_proof_data_v),
            UpdateRules::All(all) => all.verify_rules(valid_proof_data_v),
            UpdateRules::Threshold(threshold) => threshold.verify_rules(valid_proof_data_v),
        }
    }
    fn find_matching_update_keys(
        &self,
        pub_key_v: &[&MBPubKey],
        matching_pub_key_index_v: &mut Vec<usize>,
    ) {
        match self {
            UpdateRules::Key(key) => {
                key.find_matching_update_keys(pub_key_v, matching_pub_key_index_v)
            }
            UpdateRules::HashedKey(hashed_key) => {
                hashed_key.find_matching_update_keys(pub_key_v, matching_pub_key_index_v)
            }
            UpdateRules::Any(any) => {
                any.find_matching_update_keys(pub_key_v, matching_pub_key_index_v)
            }
            UpdateRules::All(all) => {
                all.find_matching_update_keys(pub_key_v, matching_pub_key_index_v)
            }
            UpdateRules::Threshold(threshold) => {
                threshold.find_matching_update_keys(pub_key_v, matching_pub_key_index_v)
            }
        }
    }
}

/// Defines the update rules for a DID document.  Note that if the value is UpdatesDisallowed,
/// then no updates to the DID are allowed, meaning that the DID is "tombstoned".
/// NOTE: In order for serialization roundtrip to work, the UpdatesDisallowed variant must be LAST.
/// This could be fixed by causing UpdatesDisallowed to be serialized as the string "UpdatesDisallowed".
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(untagged)]
pub enum RootLevelUpdateRules {
    UpdateRules(UpdateRules),
    UpdatesDisallowed(UpdatesDisallowed),
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

impl VerifyRulesT for RootLevelUpdateRules {
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
    fn find_matching_update_keys(
        &self,
        pub_key_v: &[&MBPubKey],
        matching_pub_key_index_v: &mut Vec<usize>,
    ) {
        match self {
            RootLevelUpdateRules::UpdatesDisallowed(updates_disallowed) => {
                updates_disallowed.find_matching_update_keys(pub_key_v, matching_pub_key_index_v)
            }
            RootLevelUpdateRules::UpdateRules(update_rules) => {
                update_rules.find_matching_update_keys(pub_key_v, matching_pub_key_index_v)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
    struct Stuff {
        update_rules: RootLevelUpdateRules,
    }

    fn test_update_rules_serde_json_roundtrip_case(update_rules: RootLevelUpdateRules) {
        let stuff = Stuff { update_rules };

        // Test ordinary JSON
        tracing::debug!("stuff: {:?}", stuff);
        let json = serde_json::to_string(&stuff).unwrap();
        tracing::debug!("json: {}", json);
        let parsed_json = serde_json::from_str::<Stuff>(&json).unwrap();
        tracing::debug!("parsed_json: {:?}", parsed_json);
        assert_eq!(parsed_json, stuff);

        // Also test JCS.
        let jcs = serde_json_canonicalizer::to_string(&stuff).unwrap();
        tracing::debug!("jcs: {}", jcs);
        let parsed_jcs = serde_json::from_str::<Stuff>(&jcs).unwrap();
        tracing::debug!("parsed_jcs: {:?}", parsed_jcs);
        assert_eq!(parsed_jcs, stuff);
    }

    #[test]
    fn test_update_rules_serde_json_roundtrip() {
        test_util::ctor_overall_init();

        test_update_rules_serde_json_roundtrip_case(RootLevelUpdateRules::from(UpdateKey {
            pub_key: MBPubKey::try_from("u7QEbA22Wx6DsuuqVNK04jSNYzVBx3vviEf_t4b-Xif3ZOg").unwrap(),
        }));
        test_update_rules_serde_json_roundtrip_case(RootLevelUpdateRules::from(HashedUpdateKey {
            hashed_pub_key: MBHash::try_from("uEiAWCleApqPkQg-DKbql-C5OOyZ7ydUgq7G_rHepYEukHg")
                .unwrap(),
        }));
        test_update_rules_serde_json_roundtrip_case(RootLevelUpdateRules::from(Any {
            any: vec![
                UpdateKey {
                    pub_key: MBPubKey::try_from("u7QEbA22Wx6DsuuqVNK04jSNYzVBx3vviEf_t4b-Xif3ZOg")
                        .unwrap(),
                }
                .into(),
            ],
        }));
        test_update_rules_serde_json_roundtrip_case(RootLevelUpdateRules::from(All {
            all: vec![
                UpdateKey {
                    pub_key: MBPubKey::try_from("u7QEbA22Wx6DsuuqVNK04jSNYzVBx3vviEf_t4b-Xif3ZOg")
                        .unwrap(),
                }
                .into(),
            ],
        }));
        test_update_rules_serde_json_roundtrip_case(RootLevelUpdateRules::from(Threshold {
            at_least: 2,
            of: vec![
                WeightedUpdateRules {
                    weight: 3,
                    update_rules: UpdateKey {
                        pub_key: MBPubKey::try_from(
                            "u7QEbA22Wx6DsuuqVNK04jSNYzVBx3vviEf_t4b-Xif3ZOg",
                        )
                        .unwrap(),
                    }
                    .into(),
                },
                WeightedUpdateRules {
                    weight: 1,
                    update_rules: HashedUpdateKey {
                        hashed_pub_key: MBHash::try_from(
                            "uEiAWCleApqPkQg-DKbql-C5OOyZ7ydUgq7G_rHepYEukHg",
                        )
                        .unwrap(),
                    }
                    .into(),
                },
            ],
        }));
        test_update_rules_serde_json_roundtrip_case(RootLevelUpdateRules::UpdatesDisallowed(
            UpdatesDisallowed {},
        ));
    }
}
