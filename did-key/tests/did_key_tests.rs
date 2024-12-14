use did_key::DIDStr;
use pneutype::Validate;

/// This will run once at load time (i.e. presumably before main function is called).
#[ctor::ctor]
fn overall_init() {
    env_logger::init();
}

#[test]
fn test_known_did_key_values() {
    let known_did_key_v = [
        // Ed25519
        "did:key:z6MketDdAG5qKDEcmRCZReXsVGjvfhL23G5sjJGtzWgv1jyf",
        "did:key:z6Mkfr6QBeSpjkjgZYL3377pceLRSbArTrisQQv197xpTGin",
        "did:key:z6Mkh5gkeKir86HNqd8GNZsqAwW3tuDV3upY3qcBQPUt3rsb",
        "did:key:z6MkhFAuGbu5hopAZFmf2yAn77UErFoDrCB2zwkmuKs9PVKm",
        "did:key:z6MkiY62766b1LJkExWMsM3QG4WtX7QpY823dxoYzr9qZvJ3",
        "did:key:z6Mkk46KDq8jvHrzrXVGtWQyW6PbLhfySi7fRpXueZASmuAs",
        "did:key:z6MkkGz41tg1tDsnEjaiJhPTWYj6YQkWE62t66qtXQsKLeXN",
        "did:key:z6MkkwzNunVBm27VMGmXH5oxf3WGcoNnenUfHpMbV1Uggu4G",
        "did:key:z6MkmszezrPQJF8Y4LjEfUsdzvULb2F5V6kQfeMfHRnMB691",
        "did:key:z6Mkqp14ND8S7zPXHKAR6Tex5vFgAc74EdNN5fMLYKFCMG4d",
        "did:key:z6Mku9EsTPT7pKnfTz84EfY2yadV6iUzXwXvjbzMy1TQEQ8r",
        // P-256
        // "did:key:zDnaeZ8ZzLLndZ1p6fUgqWNwraKGiZY1FEfcemE9ocW8jwsM9",

        // Secp256k1
        "did:key:zQ3shaZsYWDAoD7McrxigsboVXCZPv4rGFnpGxFnAd9As96ZM",
        "did:key:zQ3shdQDnVGCXpVDrPbEXvgvuiN5CMRyvBYnGs9wgLnSQwMB9",
        "did:key:zQ3shfvtanxFNcaLjmuQ9Jw5ex5Jsc6Abi3zP6fj8ypbUZWaF",
        "did:key:zQ3shjn77zC6LeKHzxZD55e8QrJoFb42EdmbC3tfX6J5cXN2n",
        "did:key:zQ3shn97irDtc4X832cFZVHGgGfV4CwRfDYe1sG8VuBEKmFQX",
        "did:key:zQ3shNWndTj5AeNktQYQAPaZ5xrV8ZSrEdmQs6gMZJt4LT1CV",
        "did:key:zQ3shoLh7h6T5UBCoZmdeAxx6311gW4nDXjZV8mkLnpyGikVB",
        "did:key:zQ3shP2Pz5nATkc3bpPFEhpeyzNU6FPggNKQvgznucpw6xU5u",
        "did:key:zQ3shPAAucCmbWkLUfvN7kLxSjHQZ3pJdyV2QsQdJVJcBHb9m",
        "did:key:zQ3shqypBr2ESc5hMXUuXSXna49yTdBBocbG5UfyXkvsWwCks",
        "did:key:zQ3shRffELxFPRi3P782ecRSHMsVjTcmhTajf7LPwWLrvxuvt",
        "did:key:zQ3shrrEZ2dHzGfS3QMQYEPAr3gBGTF5yTscgDENgpaoomZZ2",
        "did:key:zQ3shs8unqmumkF5dwFGU6bekE1uWDqU2NxFqH9s4j1apY811",
        "did:key:zQ3shUNxEHpDUk9sNuK6MJEydRVwXPuy2Pidscp1HR7P8oEq4",
        // Bls12381G2
        // "did:key:zUC724vuGvHpnCGFG1qqpXb81SiBLu3KLSqVzenwEZNPoY35i2Bscb8DLaVwHvRFs6F2NkNNXRcPWvqnPDUd9ukdjLkjZd3u9zzL4wDZDUpkPAatLDGLEYVo8kkAzuAKJQMr7N2",
    ];

    for known_did_key in known_did_key_v {
        tracing::debug!("validating {}", known_did_key);
        DIDStr::validate(known_did_key).expect("pass");
    }
}
