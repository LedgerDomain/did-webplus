use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashFunction {
    Blake3,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
}

#[wasm_bindgen]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Base {
    Base58Btc,
    Base64Url,
}

#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct MBHashFunction(selfhash::MBHashFunction);

#[wasm_bindgen]
impl MBHashFunction {
    pub fn new(base: Base, hash_function: HashFunction) -> Self {
        let base = match base {
            Base::Base58Btc => mbx::Base::Base58Btc,
            Base::Base64Url => mbx::Base::Base64Url,
        };
        let mb_hash_function = match hash_function {
            HashFunction::Blake3 => selfhash::MBHashFunction::blake3(base),
            HashFunction::Sha224 => selfhash::MBHashFunction::sha224(base),
            HashFunction::Sha256 => selfhash::MBHashFunction::sha256(base),
            HashFunction::Sha384 => selfhash::MBHashFunction::sha384(base),
            HashFunction::Sha512 => selfhash::MBHashFunction::sha512(base),
            HashFunction::Sha3_224 => selfhash::MBHashFunction::sha3_224(base),
            HashFunction::Sha3_256 => selfhash::MBHashFunction::sha3_256(base),
            HashFunction::Sha3_384 => selfhash::MBHashFunction::sha3_384(base),
            HashFunction::Sha3_512 => selfhash::MBHashFunction::sha3_512(base),
        };
        Self(mb_hash_function)
    }
}

impl std::ops::Deref for MBHashFunction {
    type Target = selfhash::MBHashFunction;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
