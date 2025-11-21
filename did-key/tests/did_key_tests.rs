use did_key::DIDStr;
use pneutype::Validate;

/// This will run once at load time (i.e. presumably before main function is called).
#[ctor::ctor]
fn overall_init() {
    test_util::ctor_overall_init();
}

#[test]
fn test_known_did_key_values() {
    let test_case_v = [
        // These are from:
        // - <https://github.com/w3c-ccg/did-key-spec/tree/main/test-vectors>
        // - <https://www.w3.org/TR/cid-1.0/#Multikey>

        // // bls12-381 TODO -- add support in mbx for KeyType::BLS*
        // (
        //     signature_dyn::KeyType::BLS12_381_G2_PUB,
        //     "did:key:zUC7K4ndUaGZgV7Cp2yJy6JtMoUHY6u7tkcSYUvPrEidqBmLCTLmi6d5WvwnUqejscAkERJ3bfjEiSYtdPkRSE8kSa11hFBr4sTgnbZ95SJj19PN2jdvJjyzpSZgxkyyxNnBNnY",
        // ),
        // (
        //     signature_dyn::KeyType::BLS12_381_G2_PUB,
        //     "did:key:zUC77uxiMKceQoxciSy1xgk3nvP8c8NZXDnaY1xsXZaU5UmsZdnwStUke8Ca8zAdPX3MQTHEMhDTCgfdGU7UrY4RRdVhqZp8FaAaoaXFEVp2ZAM7oj3P45BuTCfc3t9FEGBAEQY",
        // ),
        // (
        //     signature_dyn::KeyType::BLS12_381_G2_PUB,
        //     "did:key:zUC7KKoJk5ttwuuc8pmQDiUmtckEPTwcaFVZe4DSFV7fURuoRnD17D3xkBK3A9tZqdADkTTMKSwNkhjo9Hs6HfgNUXo48TNRaxU6XPLSPdRgMc15jCD5DfN34ixjoVemY62JxnW",
        // ),
        // (
        //     signature_dyn::KeyType::BLS12_381_G2_PUB,
        //     "did:key:zUC7FB43ErjeTPiBLZ8wWT3aBTL7QnJ6AAZh9opgV5dKkw291mC23yTnKQ2pTcSgLbdKnVJ1ARn6XrwxWqvFg5dRFzCjwSg1j35nRgs5c2nbqkJ4auPTyPtkJ3xcABRNWaDX6QU",
        // ),
        // (
        //     signature_dyn::KeyType::BLS12_381_G2_PUB,
        //     "did:key:zUC7FNFB7UinoJ5tqkeEELWLsytHBdHpwQ7wLVFAYRT6vqdr5uC3JPK6BVNNByj4KxvVKXoirT7VuqptSznjRCgvr7Ksuk42zyFw1GJSYNQSKCpjVcrZXoPUbR1P6zHmr97mVdA",
        // ),
        // (
        //     signature_dyn::KeyType::BLS12_381_G2_PUB,
        //     // <https://w3c-ccg.github.io/did-key-spec/#bls-12-381>
        //     "did:key:zUC7K4ndUaGZgV7Cp2yJy6JtMoUHY6u7tkcSYUvPrEidqBmLCTLmi6d5WvwnUqejscAkERJ3bfjEiSYtdPkRSE8kSa11hFBr4sTgnbZ95SJj19PN2jdvJjyzpSZgxkyyxNnBNnY",
        // ),
        // (
        //     signature_dyn::KeyType::BLS12_381_G2_PUB,
        //     // <https://w3c-ccg.github.io/did-key-spec/#bls-12-381>
        //     "did:key:zUC7KKoJk5ttwuuc8pmQDiUmtckEPTwcaFVZe4DSFV7fURuoRnD17D3xkBK3A9tZqdADkTTMKSwNkhjo9Hs6HfgNUXo48TNRaxU6XPLSPdRgMc15jCD5DfN34ixjoVemY62JxnW",
        // ),
        // (
        //     signature_dyn::KeyType::BLS12_381_G1G2_PUB,
        //     "did:key:z5TcCmGLu7HrkT5FTnejDTKcH11LPMQLXMPHTRyzY4KdRvqpPLprH7s1ddWFD38cAkZoiDtofUmJVZyEweUTfwjG5H3znk3ir4tzmuDBUSNbNQ7U6jJqj5bkQLKRaQB1bpFJKGLEq3EBwsfPutL5D7p78kFeLNHznqbf5oGpik7ScaDbGLaTLh1Jtadi6VmPNNd44Cojk",
        // ),
        // ed25519
        (
            signature_dyn::KeyType::Ed25519,
            "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp",
        ),
        (
            signature_dyn::KeyType::Ed25519,
            "did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG",
        ),
        (
            signature_dyn::KeyType::Ed25519,
            "did:key:z6MknGc3ocHs3zdPiJbnaaqDi58NGb4pk1Sp9WxWufuXSdxf",
        ),
        (
            signature_dyn::KeyType::Ed25519,
            "did:key:z6MkvqoYXQfDDJRv8L4wKzxYeuKyVZBfi9Qo6Ro8MiLH3kDQ",
        ),
        (
            signature_dyn::KeyType::Ed25519,
            "did:key:z6MkwYMhwTvsq376YBAcJHy3vyRWzBgn5vKfVqqDCgm7XVKU",
        ),
        (
            signature_dyn::KeyType::Ed25519,
            "did:key:z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu",
        ),
        // TODO: Some ed448 test vectors
        // p256
        (
            signature_dyn::KeyType::P256,
            // <https://github.com/bshambaugh/did-key-creator>
            "did:key:zDnaeqYWNxcFqy5DcJm91BMTeWv5hjs1VL5medk9n8dDUC67T",
        ),
        (
            signature_dyn::KeyType::P256,
            // <https://w3c-ccg.github.io/did-key-spec/#p-256>
            "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169",
        ),
        (
            signature_dyn::KeyType::P256,
            // <https://w3c-ccg.github.io/did-key-spec/#p-256>
            "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv",
        ),
        // p384
        (
            signature_dyn::KeyType::P384,
            // <https://github.com/bshambaugh/did-key-creator>
            "did:key:z82Lkz6GT5oNPzQowVWaYysnFPT1NAMsXayELmNjme3FhRErkTkij9ywuYWukxcLfNdW6Cw",
        ),
        (
            signature_dyn::KeyType::P384,
            // <https://w3c-ccg.github.io/did-key-spec/#p-384>
            "did:key:z82Lm1MpAkeJcix9K8TMiLd5NMAhnwkjjCBeWHXyu3U4oT2MVJJKXkcVBgjGhnLBn2Kaau9",
        ),
        (
            signature_dyn::KeyType::P384,
            // <https://w3c-ccg.github.io/did-key-spec/#p-384>
            "did:key:z82LkvCwHNreneWpsgPEbV3gu1C6NFJEBg4srfJ5gdxEsMGRJUz2sG9FE42shbn2xkZJh54",
        ),
        // p521
        (
            signature_dyn::KeyType::P521,
            // <https://github.com/bshambaugh/did-key-creator>
            "did:key:z2J9gaYmUxgiF1VDutBWwC4KVdpKfjnRkyV3t4kysx49eHz1wkYh1KHBPqbNdVH5GTgY2KLXtJPYTwFDkhQxuTWxK3K5HSKu",
        ),
        // secp256k1
        (
            signature_dyn::KeyType::Secp256k1,
            "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme",
        ),
        (
            signature_dyn::KeyType::Secp256k1,
            "did:key:zQ3shtxV1FrJfhqE1dvxYRcCknWNjHc3c5X1y3ZSoPDi2aur2",
        ),
        (
            signature_dyn::KeyType::Secp256k1,
            "did:key:zQ3shZc2QzApp2oymGvQbzP8eKheVshBHbU4ZYjeXqwSKEn6N",
        ),
        (
            signature_dyn::KeyType::Secp256k1,
            "did:key:zQ3shadCps5JLAHcZiuX5YUtWHHL8ysBJqFLWvjZDKAWUBGzy",
        ),
        (
            signature_dyn::KeyType::Secp256k1,
            "did:key:zQ3shptjE6JwdkeKN4fcpnYQY3m9Cet3NiHdAfpvSUZBFoKBj",
        ),
        (
            signature_dyn::KeyType::Secp256k1,
            "did:key:zQ3shjmnWpSDEbYKpaFm4kTs9kXyqG6N2QwCYHNPP4yubqgJS",
        ),
        // TODO: some that use base64
    ];

    for (expected_key_type, did_key_str) in test_case_v {
        tracing::debug!("validating {}", did_key_str);
        DIDStr::validate(did_key_str).expect("pass");
        let did = DIDStr::new_ref(did_key_str).expect("pass");

        let pub_key = mbx::MBPubKeyStr::new_ref(did.multibase()).expect("pass");
        tracing::debug!(
            "pub_key: {:?}, pub_key.try_into_key_type(): {:?}",
            pub_key,
            pub_key.try_into_key_type()
        );
        assert_eq!(
            pub_key.try_into_key_type().expect("pass"),
            expected_key_type
        );
    }
}
