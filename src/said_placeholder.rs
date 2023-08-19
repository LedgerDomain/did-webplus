pub fn said_placeholder(hash_function_code: &said::derivation::HashFunctionCode) -> &'static str {
    const PLACEHOLDER_44_CHARS: &str = "############################################";
    const PLACEHOLDER_88_CHARS: &str =
        "########################################################################################";
    match hash_function_code {
        said::derivation::HashFunctionCode::Blake3_256 => PLACEHOLDER_44_CHARS,
        said::derivation::HashFunctionCode::Blake2B256(_) => PLACEHOLDER_44_CHARS,
        said::derivation::HashFunctionCode::Blake2S256(_) => PLACEHOLDER_44_CHARS,
        said::derivation::HashFunctionCode::SHA3_256 => PLACEHOLDER_44_CHARS,
        said::derivation::HashFunctionCode::SHA2_256 => PLACEHOLDER_44_CHARS,
        said::derivation::HashFunctionCode::Blake3_512 => PLACEHOLDER_88_CHARS,
        said::derivation::HashFunctionCode::SHA3_512 => PLACEHOLDER_88_CHARS,
        said::derivation::HashFunctionCode::Blake2B512 => PLACEHOLDER_88_CHARS,
        said::derivation::HashFunctionCode::SHA2_512 => PLACEHOLDER_88_CHARS,
    }
}

pub fn said_placeholder_for_uri(
    hash_function_code: &said::derivation::HashFunctionCode,
) -> &'static str {
    const PLACEHOLDER_44_CHARS: &str = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    const PLACEHOLDER_88_CHARS: &str =
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    match hash_function_code {
        said::derivation::HashFunctionCode::Blake3_256 => PLACEHOLDER_44_CHARS,
        said::derivation::HashFunctionCode::Blake2B256(_) => PLACEHOLDER_44_CHARS,
        said::derivation::HashFunctionCode::Blake2S256(_) => PLACEHOLDER_44_CHARS,
        said::derivation::HashFunctionCode::SHA3_256 => PLACEHOLDER_44_CHARS,
        said::derivation::HashFunctionCode::SHA2_256 => PLACEHOLDER_44_CHARS,
        said::derivation::HashFunctionCode::Blake3_512 => PLACEHOLDER_88_CHARS,
        said::derivation::HashFunctionCode::SHA3_512 => PLACEHOLDER_88_CHARS,
        said::derivation::HashFunctionCode::Blake2B512 => PLACEHOLDER_88_CHARS,
        said::derivation::HashFunctionCode::SHA2_512 => PLACEHOLDER_88_CHARS,
    }
}
