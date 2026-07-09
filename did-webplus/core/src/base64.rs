/// This function is to assist in no-alloc base64 encoding of 256 bits.
pub fn base64_encode_256_bits<'a>(input_byte_v: &[u8; 32], buffer: &'a mut [u8; 43]) -> &'a str {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode_slice(input_byte_v, buffer)
        .unwrap();
    std::str::from_utf8(&*buffer).unwrap()
}

/// This function is to assist in no-alloc base64 encoding of 384 bits.
pub fn base64_encode_384_bits<'a>(input_byte_v: &[u8; 48], buffer: &'a mut [u8; 64]) -> &'a str {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode_slice(input_byte_v, buffer)
        .unwrap();
    std::str::from_utf8(&*buffer).unwrap()
}

/// This function is to assist in no-alloc base64 encoding of 456 bits (for use with ed448 pub keys, which are 57 bytes).
pub fn base64_encode_456_bits<'a>(input_byte_v: &[u8; 57], buffer: &'a mut [u8; 76]) -> &'a str {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode_slice(input_byte_v, buffer)
        .unwrap();
    std::str::from_utf8(&*buffer).unwrap()
}

/// This function is to assist in no-alloc base64 encoding of 521 bits.
pub fn base64_encode_521_bits<'a>(input_byte_v: &[u8; 66], buffer: &'a mut [u8; 88]) -> &'a str {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode_slice(input_byte_v, buffer)
        .unwrap();
    std::str::from_utf8(&*buffer).unwrap()
}

/// This function is to assist in no-alloc base64 decoding of 256 bits.
/// 256 bits is 43 base64 chars (rounded up), but 43 base64 chars is 258 bits,
/// so there has to be an extra byte in the buffer for base64 to decode into.
pub fn base64_decode_256_bits<'a>(
    input_str: &str,
    buffer: &'a mut [u8; 33],
) -> crate::Result<&'a [u8; 32]> {
    use crate::Error;

    if !input_str.is_ascii() {
        return Err(Error::Malformed("not ASCII".into()));
    }
    if input_str.len() != 43 {
        return Err(Error::Malformed("expected 43 base64 chars".into()));
    }
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode_slice(input_str.as_bytes(), buffer)
        .map_err(|_| "base64 decode of 256 bit value failed")?;
    // Ensure that the last byte is zero, otherwise there were more than 256 bits in the base64 string.
    if buffer[32] != 0 {
        return Err(Error::Malformed("does not parse as 256 bit value".into()));
    }
    // Cut off the last byte, which we know is zero.
    let output_byte_v: &[u8; 32] = buffer[0..32].try_into().unwrap();
    Ok(output_byte_v)
}

/// This function is to assist in no-alloc base64 decoding of 384 bits.  384 bits is 64 base64 chars.
pub fn base64_decode_384_bits<'a>(
    input_str: &str,
    buffer: &'a mut [u8; 48],
) -> crate::Result<&'a [u8; 48]> {
    use crate::Error;

    if !input_str.is_ascii() {
        return Err(Error::Malformed("not ASCII".into()));
    }
    if input_str.len() != 64 {
        return Err(Error::Malformed("expected 64 base64 chars".into()));
    }
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode_slice(input_str.as_bytes(), buffer)
        .map_err(|_| "base64 decode of 384 bit value failed")?;
    let output_byte_v: &[u8; 48] = &*buffer;
    Ok(output_byte_v)
}

/// This function is to assist in no-alloc base64 decoding of 456 bits, which is exactly 76 base64 chars.
pub fn base64_decode_456_bits<'a>(
    input_str: &str,
    buffer: &'a mut [u8; 57],
) -> crate::Result<&'a [u8; 57]> {
    use crate::Error;

    if !input_str.is_ascii() {
        return Err(Error::Malformed("not ASCII".into()));
    }
    if input_str.len() != 76 {
        return Err(Error::Malformed("expected 76 base64 chars".into()));
    }
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode_slice(input_str.as_bytes(), buffer)
        .map_err(|_| "base64 decode of 456 bit value failed")?;
    let output_byte_v: &[u8; 57] = buffer[0..57].try_into().unwrap();
    Ok(output_byte_v)
}

/// This function is to assist in no-alloc base64 decoding of 521 bits, which requires 88
/// base64 chars (due to rounding 521 up to 528).
pub fn base64_decode_521_bits<'a>(
    input_str: &str,
    buffer: &'a mut [u8; 66],
) -> crate::Result<&'a [u8; 66]> {
    use crate::Error;

    if !input_str.is_ascii() {
        return Err(Error::Malformed("not ASCII".into()));
    }
    if input_str.len() != 88 {
        return Err(Error::Malformed("expected 88 base64 chars".into()));
    }
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode_slice(input_str.as_bytes(), buffer)
        .map_err(|_| "base64 decode of 521 bit value failed")?;
    let output_byte_v: &[u8; 66] = &*buffer;
    Ok(output_byte_v)
}

#[cfg(test)]
mod tests {
    use rand::RngCore;

    use super::*;

    #[test]
    fn test_base64_encode_decode_256_bits() {
        for _ in 0..1000 {
            let mut input_byte_v = [0u8; 32];
            // Fill the input byte vector with a random value.
            rand::thread_rng().fill_bytes(&mut input_byte_v);
            let mut encode_buffer = [0u8; 43];
            let output_str = base64_encode_256_bits(&input_byte_v, &mut encode_buffer);
            let mut decode_buffer = [0u8; 33];
            let output_byte_v = base64_decode_256_bits(output_str, &mut decode_buffer).unwrap();
            assert_eq!(output_byte_v, &input_byte_v);
        }
    }

    #[test]
    fn test_base64_encode_decode_384_bits() {
        for _ in 0..1000 {
            let mut input_byte_v = [0u8; 48];
            // Fill the input byte vector with a random value.
            rand::thread_rng().fill_bytes(&mut input_byte_v);
            let mut encode_buffer = [0u8; 64];
            let output_str = base64_encode_384_bits(&input_byte_v, &mut encode_buffer);
            let mut decode_buffer = [0u8; 48];
            let output_byte_v = base64_decode_384_bits(output_str, &mut decode_buffer).unwrap();
            assert_eq!(output_byte_v, &input_byte_v);
        }
    }

    #[test]
    fn test_base64_encode_decode_456_bits() {
        for _ in 0..1000 {
            let mut input_byte_v = [0u8; 57];
            // Fill the input byte vector with a random value.
            rand::thread_rng().fill_bytes(&mut input_byte_v);
            let mut encode_buffer = [0u8; 76];
            let output_str = base64_encode_456_bits(&input_byte_v, &mut encode_buffer);
            let mut decode_buffer = [0u8; 57];
            let output_byte_v = base64_decode_456_bits(output_str, &mut decode_buffer).unwrap();
            assert_eq!(output_byte_v, &input_byte_v);
        }
    }

    #[test]
    fn test_base64_encode_decode_521_bits() {
        for _ in 0..1000 {
            let mut input_byte_v = [0u8; 66];
            // Fill the input byte vector with a random value.
            rand::thread_rng().fill_bytes(&mut input_byte_v);
            let mut encode_buffer = [0u8; 88];
            let output_str = base64_encode_521_bits(&input_byte_v, &mut encode_buffer);
            let mut decode_buffer = [0u8; 66];
            let output_byte_v = base64_decode_521_bits(output_str, &mut decode_buffer).unwrap();
            assert_eq!(output_byte_v, &input_byte_v);
        }
    }
}
