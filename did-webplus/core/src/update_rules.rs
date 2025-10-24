use crate::{Error, Result};
use mbx::{MBHash, MBHashStr, MBPubKey, MBPubKeyStr};

#[derive(Clone, Debug)]
pub struct ValidProofData {
    pub_key: MBPubKey,
    // NOTE: For now we always assume Base64Url encoding on a Blake3 hash.
    hashed_pub_key: MBHash,
}

impl ValidProofData {
    pub fn from_pub_key(pub_key: MBPubKey) -> Self {
        use selfhash::HashFunctionT;
        let mut hasher = selfhash::MBHashFunction::blake3(mbx::Base::Base64Url).new_hasher();
        use selfhash::HasherT;
        hasher.update(pub_key.as_bytes());
        let hashed_pub_key = hasher.finalize();
        Self {
            pub_key,
            hashed_pub_key,
        }
    }
    pub fn pub_key(&self) -> &MBPubKeyStr {
        self.pub_key.as_mb_pub_key_str()
    }
    pub fn hashed_pub_key(&self) -> &MBHashStr {
        self.hashed_pub_key.as_mb_hash_str()
    }
}

pub trait VerifyRulesT {
    fn verify_rules(&self, valid_proof_data_v: &[ValidProofData]) -> Result<()>;
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct UpdatesDisallowed {}

impl VerifyRulesT for UpdatesDisallowed {
    fn verify_rules(&self, _valid_proof_key_v: &[ValidProofData]) -> Result<()> {
        Err(Error::InvalidDIDUpdateOperation("UpdatesDisallowed"))
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
        // TODO: Give details about which rules failed.  This potentially affects the UX.
        Err(Error::InvalidDIDUpdateOperation("Key"))
    }
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct HashedUpdateKey {
    #[serde(rename = "hashedKey")]
    hashed_pub_key: MBHash,
}

impl HashedUpdateKey {
    pub fn from_pub_key(pub_key: &MBPubKeyStr) -> Self {
        use selfhash::HashFunctionT;
        let mut hasher = selfhash::MBHashFunction::blake3(mbx::Base::Base64Url).new_hasher();
        use selfhash::HasherT;
        hasher.update(pub_key.as_bytes());
        let hashed_pub_key = hasher.finalize();
        Self { hashed_pub_key }
    }
    pub fn from_hashed_pub_key(hashed_pub_key: MBHash) -> Self {
        Self { hashed_pub_key }
    }
    pub fn hashed_pub_key(&self) -> &MBHashStr {
        self.hashed_pub_key.as_mb_hash_str()
    }
}

impl VerifyRulesT for HashedUpdateKey {
    fn verify_rules(&self, valid_proof_data_v: &[ValidProofData]) -> Result<()> {
        for valid_proof_key in valid_proof_data_v.iter() {
            if valid_proof_key.hashed_pub_key() == self.hashed_pub_key.as_mb_hash_str() {
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

impl VerifyRulesT for Any {
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

impl VerifyRulesT for All {
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
            panic!(
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
