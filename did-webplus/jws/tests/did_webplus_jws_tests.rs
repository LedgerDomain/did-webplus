use did_webplus_jws::{JOSEAlgorithmT, JWSPayloadEncoding, JWSPayloadPresence, JWS};

fn test_jws_impl<
    Signature: std::fmt::Debug + signature::SignatureEncoding,
    Signer: signature::Signer<Signature> + JOSEAlgorithmT,
    Verifier: signature::Verifier<Signature> + JOSEAlgorithmT,
>(
    signing_key: &Signer,
    verifying_key: &Verifier,
) {
    println!(
        "--------- testing JWS with alg {:?} and crv {:?}",
        signing_key.alg(),
        signing_key.crv_o()
    );
    let payload = r#""HIPPO WORLD!""#.as_bytes();
    for payload_presence in [JWSPayloadPresence::Attached, JWSPayloadPresence::Detached] {
        for payload_encoding in [JWSPayloadEncoding::Base64, JWSPayloadEncoding::None] {
            println!("    --------------------------------");
            println!(
                "    payload_presence: {:?}, payload_encoding: {:?}",
                payload_presence, payload_encoding
            );
            let jws = JWS::signed2(
                "fancy key".to_string(),
                &mut &*payload,
                payload_presence,
                payload_encoding,
                signing_key,
            )
            .expect("pass");
            println!("    jws: {}", jws);
            if payload_presence == JWSPayloadPresence::Detached {
                jws.verify2(verifying_key, Some(&mut &*payload))
                    .expect("pass");
            } else {
                jws.verify2(verifying_key, None).expect("pass");
            }
        }
    }
}

#[cfg(feature = "ed25519-dalek")]
#[test]
fn test_jws_ed25519_dalek() {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let verifying_key = signing_key.verifying_key();
    test_jws_impl(&signing_key, &verifying_key);
}

#[cfg(feature = "k256")]
#[test]
fn test_jws_k256() {
    let signing_key = k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
    let verifying_key = signing_key.verifying_key();
    test_jws_impl::<k256::ecdsa::Signature, k256::ecdsa::SigningKey, k256::ecdsa::VerifyingKey>(
        &signing_key,
        verifying_key,
    );
}

// TODO: Add support in jws.rs for p256.
// #[cfg(feature = "p256")]
// #[test]
// fn test_jws_p256() {
//     let signing_key = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
//     let verifying_key = signing_key.verifying_key();
//     test_jws_impl::<p256::ecdsa::Signature, p256::ecdsa::SigningKey, p256::ecdsa::VerifyingKey>(
//         &signing_key,
//         verifying_key,
//     );
// }
