use crate::{Result, SelfHashArgs};
use selfhash::{HashFunction, SelfHashable};
use std::{
    borrow::Cow,
    io::{Read, Write},
};

/// Read JSON from stdin and write self-hashed but non-signed Verifiable JSON (VJSON) to stdout.
///
/// Compute the Verifiable JSON (VJSON) from the given JSON input read from stdin.  Verifiable JSON
/// self-validating by using of a self-hashing procedure.  In particular, VJSON has at least one
/// "self-hash slot" which is used during the computation and verification of the JSON's self-hash.
/// During the computation of the JSON's self-hash, all the self-hash slots are set to a placeholder
/// value which encodes which hash function will be used, the JSON is serialized into JCS (JSON
/// Canonicalization Scheme), and then hashed.  This hash value is then used to set all the self-hash slots.
/// The JSON is then serialized into JCS again, and at this point is self-hashed and fully self-verifiable,
/// and is called VJSON.
#[derive(clap::Args)]
pub struct VJSONSelfHash {
    #[command(flatten)]
    pub self_hash_args: SelfHashArgs,
    /// If specified, don't print a trailing newline in the output [default: print newline].
    #[arg(short, long)]
    pub no_newline: bool,
}

impl VJSONSelfHash {
    pub fn handle(self) -> Result<()> {
        // Read all of stdin into a String and parse it as JSON.
        let mut input = String::new();
        std::io::stdin().read_to_string(&mut input).unwrap();
        let value = serde_json::from_str(&input).unwrap();

        // Parse the self-hash related arguments.
        let self_hash_path_s = self.self_hash_args.parse_self_hash_paths();
        let self_hash_url_path_s = self.self_hash_args.parse_self_hash_url_paths();

        // Set up the context for self-hashable JSON.
        let mut json = selfhash::SelfHashableJSON::new(
            value,
            Cow::Borrowed(&self_hash_path_s),
            Cow::Borrowed(&self_hash_url_path_s),
        )
        .unwrap();

        // Self-hash the JSON.
        // TODO: Arg to specify the hash function
        json.self_hash(selfhash::Blake3.new_hasher())
            .expect("self-hash failed");

        // Verify the self-hash.  This is mostly a sanity check.
        json.verify_self_hashes()
            .expect("programmer error: self-hash verification failed");

        // Print the self-hashed JSON and optional newline.
        serde_json_canonicalizer::to_writer(json.value(), &mut std::io::stdout()).unwrap();
        if !self.no_newline {
            std::io::stdout().write("\n".as_bytes()).unwrap();
        }

        Ok(())
    }
}
