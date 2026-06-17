use did_webplus_jws::{JWS, JWSPayloadEncoding, JWSPayloadPresence};

fn test_jws_impl(signer: &dyn signature_dyn::SignerT, verifier: &dyn signature_dyn::VerifierT) {
    println!(
        "--------- testing JWS with alg {:?}",
        signer.key_type().jose_algorithm(),
    );
    let payload = r#""HIPPO WORLD!""#.as_bytes();
    for payload_presence in [JWSPayloadPresence::Attached, JWSPayloadPresence::Detached] {
        for payload_encoding in [JWSPayloadEncoding::Base64, JWSPayloadEncoding::None] {
            println!("    --------------------------------");
            println!(
                "    payload_presence: {:?}, payload_encoding: {:?}",
                payload_presence, payload_encoding
            );
            let jws = JWS::signed(
                "fancy key".to_string(),
                &mut &*payload,
                payload_presence,
                payload_encoding,
                signer,
            )
            .expect("pass");
            println!("    jws: {}", jws);
            if payload_presence == JWSPayloadPresence::Detached {
                jws.verify(verifier, Some(&mut &*payload)).expect("pass");
            } else {
                jws.verify(verifier, None).expect("pass");
            }
        }
    }
}

#[cfg(feature = "ed25519-dalek")]
#[test]
fn test_jws_ed25519_dalek() {
    use signature_dyn::GenerateRandom;
    let signing_key = ed25519_dalek::SigningKey::generate_random();
    let verifying_key = signing_key.verifying_key();
    test_jws_impl(&signing_key, &verifying_key);
}

#[cfg(feature = "ed448-goldilocks")]
#[test]
fn test_jws_ed448_goldilocks() {
    use ed448_goldilocks::elliptic_curve::Generate;
    let signing_key = ed448_goldilocks::SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    test_jws_impl(&signing_key, &verifying_key);
}

#[cfg(feature = "k256")]
#[test]
fn test_jws_k256() {
    use signature_dyn::GenerateRandom;
    let signing_key = k256::ecdsa::SigningKey::generate_random();
    let verifying_key = signing_key.verifying_key();
    test_jws_impl(&signing_key, verifying_key);
}

#[cfg(feature = "p256")]
#[test]
fn test_jws_p256() {
    use signature_dyn::GenerateRandom;
    let signing_key = p256::ecdsa::SigningKey::generate_random();
    let verifying_key = signing_key.verifying_key();
    test_jws_impl(&signing_key, verifying_key);
}

#[cfg(feature = "p384")]
#[test]
fn test_jws_p384() {
    use signature_dyn::GenerateRandom;
    let signing_key = p384::ecdsa::SigningKey::generate_random();
    let verifying_key = signing_key.verifying_key();
    test_jws_impl(&signing_key, verifying_key);
}

#[cfg(feature = "p521")]
#[test]
fn test_jws_p521() {
    use p521::elliptic_curve::Generate;
    let signing_key = p521::ecdsa::SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    test_jws_impl(&signing_key, verifying_key);
}
