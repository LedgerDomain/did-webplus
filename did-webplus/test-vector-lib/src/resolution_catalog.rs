//! Resolution-URL relative negatives: valid microledgers served under a mismatched DID.
//!
//! Each vector's `did-documents.jsonl` is cryptographically and structurally valid on
//! its own. [`TestVector::did`] is the **resolution** DID implied by the serving host
//! and on-disk path (what a VDR would derive from the fetch URL). Harnesses that only
//! validate the jsonl body will accept these; harnesses that also require
//! `document.id == resolution DID` must reject them.

use did_webplus_core::DID;

use crate::{
    DeterministicRng, ErrorCode, Expected, MicroledgerBuilder, TestVector, TestVectorParams,
    VectorDefinition,
};

const CATEGORY: &str = "resolution";
const RESOLUTION_REF: &str = "#resolution-url";
/// Extra path component used to diverge resolution URL path from content DID path.
const EXTRA_PATH_COMPONENT: &str = "extra";
/// Foreign DID host used when the resolution / VDR host is the catalog `--host`.
const FOREIGN_HOST: &str = "hippo.mom";
/// Content DID port when the catalog / VDR has no `--port`.
const DEFAULT_FOREIGN_PORT: u16 = 12345;
/// Alternate content DID port when the catalog / VDR `--port` is [`DEFAULT_FOREIGN_PORT`].
const ALTERNATE_FOREIGN_PORT: u16 = 12346;

/// Port for the content DID: always present, and never equal to the VDR / catalog port.
fn mismatched_content_port(vdr_port_o: Option<u16>) -> u16 {
    match vdr_port_o {
        None => DEFAULT_FOREIGN_PORT,
        Some(port) if port == DEFAULT_FOREIGN_PORT => ALTERNATE_FOREIGN_PORT,
        Some(_) => DEFAULT_FOREIGN_PORT,
    }
}

fn path_o(path_component_v: &[String]) -> Option<String> {
    if path_component_v.is_empty() {
        None
    } else {
        Some(path_component_v.join(":"))
    }
}

fn resolution_did(
    host: &str,
    port_o: Option<u16>,
    path_component_v: &[String],
    root_self_hash: &mbx::MBHashStr,
) -> anyhow::Result<DID> {
    DID::new(
        host,
        port_o,
        path_o(path_component_v).as_deref(),
        root_self_hash,
    )
    .map_err(Into::into)
}

fn vector(
    name: &str,
    description: &str,
    content_params: TestVectorParams,
    jsonl_line_v: Vec<String>,
    resolution_did: DID,
    error_code: ErrorCode,
) -> TestVector {
    let count = jsonl_line_v.len() as u32;
    TestVector {
        name: name.to_owned(),
        category: CATEGORY.to_owned(),
        description: description.to_owned(),
        spec_ref_v: vec![RESOLUTION_REF.to_owned()],
        jsonl_line_v,
        did: resolution_did,
        expected: Expected::reject_after(count, 0, error_code, 0),
        params: content_params,
    }
}

/// Valid microledger placed under a different root self-hash directory.
fn root_self_hash_mismatch(
    params: TestVectorParams,
    rng: DeterministicRng,
) -> anyhow::Result<TestVector> {
    let builder = MicroledgerBuilder::create_with_updates(params.clone(), rng, 1)?;
    let content_did = builder.did().clone();
    let jsonl_line_v = builder.canonical_jsonl_lines()?;

    // Second valid ledger supplies a well-formed alternate root self-hash.
    let decoy = MicroledgerBuilder::create(
        params.clone(),
        DeterministicRng::for_vector("resolution-decoy", "root-self-hash-mismatch"),
    )?;
    let wrong_hash = decoy.did().root_self_hash();
    anyhow::ensure!(
        wrong_hash != content_did.root_self_hash(),
        "decoy root self-hash unexpectedly equals content root self-hash"
    );

    let resolution_did = resolution_did(
        &params.host,
        params.port_o,
        &params.path_component_v,
        wrong_hash,
    )?;
    Ok(vector(
        "resolution-root-self-hash-mismatch",
        "Valid microledger served under a resolution URL whose root self-hash differs from the DID inside did-documents.jsonl.",
        params,
        jsonl_line_v,
        resolution_did,
        ErrorCode::ResolutionRootSelfHashMismatch,
    ))
}

/// Resolution path has an extra component relative to the content DID.
fn path_url_has_extra(params: TestVectorParams, rng: DeterministicRng) -> anyhow::Result<TestVector> {
    let builder = MicroledgerBuilder::create_with_updates(params.clone(), rng, 1)?;
    let content_did = builder.did().clone();
    let jsonl_line_v = builder.canonical_jsonl_lines()?;

    let mut resolution_path_component_v = params.path_component_v.clone();
    resolution_path_component_v.push(EXTRA_PATH_COMPONENT.to_owned());
    let resolution_did = resolution_did(
        &params.host,
        params.port_o,
        &resolution_path_component_v,
        content_did.root_self_hash(),
    )?;
    anyhow::ensure!(
        content_did.path_o() != resolution_did.path_o(),
        "resolution path should include an extra component"
    );

    Ok(vector(
        "resolution-path-url-has-extra",
        "Valid microledger whose resolution URL has extra path element(s) relative to the DID inside did-documents.jsonl (root self-hash matches).",
        params,
        jsonl_line_v,
        resolution_did,
        ErrorCode::ResolutionPathMismatch,
    ))
}

/// Content DID has an extra path component relative to the resolution URL.
fn path_content_has_extra(
    params: TestVectorParams,
    rng: DeterministicRng,
) -> anyhow::Result<TestVector> {
    let mut content_params = params.clone();
    content_params
        .path_component_v
        .push(EXTRA_PATH_COMPONENT.to_owned());
    let builder = MicroledgerBuilder::create_with_updates(content_params.clone(), rng, 1)?;
    let content_did = builder.did().clone();
    let jsonl_line_v = builder.canonical_jsonl_lines()?;

    let resolution_did = resolution_did(
        &params.host,
        params.port_o,
        &params.path_component_v,
        content_did.root_self_hash(),
    )?;
    anyhow::ensure!(
        content_did.path_o() != resolution_did.path_o(),
        "content DID path should include an extra component"
    );

    Ok(vector(
        "resolution-path-content-has-extra",
        "Valid microledger whose DID path has extra element(s) relative to the resolution URL (root self-hash matches).",
        content_params,
        jsonl_line_v,
        resolution_did,
        ErrorCode::ResolutionPathMismatch,
    ))
}

/// Content DID host differs from the catalog / VDR `--host`.
fn host_mismatch(params: TestVectorParams, rng: DeterministicRng) -> anyhow::Result<TestVector> {
    anyhow::ensure!(
        params.host != FOREIGN_HOST,
        "catalog --host must not be {FOREIGN_HOST:?} when generating the host-mismatch vector"
    );
    let mut content_params = params.clone();
    content_params.host = FOREIGN_HOST.to_owned();
    let builder = MicroledgerBuilder::create_with_updates(content_params.clone(), rng, 1)?;
    let content_did = builder.did().clone();
    let jsonl_line_v = builder.canonical_jsonl_lines()?;

    let resolution_did = resolution_did(
        &params.host,
        params.port_o,
        &params.path_component_v,
        content_did.root_self_hash(),
    )?;
    anyhow::ensure!(
        content_did.hostname() != resolution_did.hostname(),
        "content host should differ from resolution host"
    );

    Ok(vector(
        "resolution-host-mismatch",
        "Valid microledger whose DID host differs from the VDR / catalog --host while path and root self-hash match the resolution URL.",
        content_params,
        jsonl_line_v,
        resolution_did,
        ErrorCode::ResolutionHostMismatch,
    ))
}

/// Content DID always has a port that differs from the catalog / VDR `--port`.
fn port_mismatch(params: TestVectorParams, rng: DeterministicRng) -> anyhow::Result<TestVector> {
    let content_port = mismatched_content_port(params.port_o);
    let mut content_params = params.clone();
    content_params.port_o = Some(content_port);
    let builder = MicroledgerBuilder::create_with_updates(content_params.clone(), rng, 1)?;
    let content_did = builder.did().clone();
    let jsonl_line_v = builder.canonical_jsonl_lines()?;

    let resolution_did = resolution_did(
        &params.host,
        params.port_o,
        &params.path_component_v,
        content_did.root_self_hash(),
    )?;
    anyhow::ensure!(
        content_did.port_o() == Some(content_port),
        "content DID must include port {content_port}"
    );
    anyhow::ensure!(
        content_did.port_o() != resolution_did.port_o(),
        "content port should differ from resolution / VDR port"
    );

    Ok(vector(
        "resolution-port-mismatch",
        "Valid microledger whose DID port differs from the VDR / catalog --port (content DID always includes a port) while host, path, and root self-hash match the resolution URL.",
        content_params,
        jsonl_line_v,
        resolution_did,
        ErrorCode::ResolutionPortMismatch,
    ))
}

pub(crate) fn definitions() -> &'static [VectorDefinition] {
    const DEFINITIONS: &[VectorDefinition] = &[
        VectorDefinition {
            name: "resolution-root-self-hash-mismatch",
            description: "Valid microledger served under a resolution URL whose root self-hash differs from the DID inside did-documents.jsonl.",
            positive: false,
            factory: root_self_hash_mismatch,
        },
        VectorDefinition {
            name: "resolution-path-url-has-extra",
            description: "Valid microledger whose resolution URL has extra path element(s) relative to the DID inside did-documents.jsonl (root self-hash matches).",
            positive: false,
            factory: path_url_has_extra,
        },
        VectorDefinition {
            name: "resolution-path-content-has-extra",
            description: "Valid microledger whose DID path has extra element(s) relative to the resolution URL (root self-hash matches).",
            positive: false,
            factory: path_content_has_extra,
        },
        VectorDefinition {
            name: "resolution-host-mismatch",
            description: "Valid microledger whose DID host differs from the VDR / catalog --host while path and root self-hash match the resolution URL.",
            positive: false,
            factory: host_mismatch,
        },
        VectorDefinition {
            name: "resolution-port-mismatch",
            description: "Valid microledger whose DID port differs from the VDR / catalog --port (content DID always includes a port) while host, path, and root self-hash match the resolution URL.",
            positive: false,
            factory: port_mismatch,
        },
    ];
    DEFINITIONS
}

#[cfg(test)]
mod tests {
    use super::*;
    use did_webplus_core::DIDDocument;

    fn content_did(vector: &TestVector) -> DID {
        let document: DIDDocument =
            serde_json::from_str(&vector.jsonl_line_v[0]).expect("root document JSON");
        document.did
    }

    #[test]
    fn every_resolution_vector_has_valid_body_and_mismatched_resolution_did() {
        let params = TestVectorParams::baseline("example.com");
        for definition in definitions() {
            let vector = (definition.factory)(
                params.clone(),
                DeterministicRng::for_vector("resolution-unit", definition.name),
            )
            .expect(definition.name);
            assert_eq!(vector.category, CATEGORY);
            assert!(!vector.expected.is_fully_valid());
            assert_eq!(vector.expected.valid_did_document_count, 0);
            assert!(!vector.jsonl_line_v.is_empty());

            let inside = content_did(&vector);
            assert_ne!(inside, vector.did, "{}", definition.name);

            match vector.expected.error_code_o {
                Some(ErrorCode::ResolutionRootSelfHashMismatch) => {
                    assert_eq!(inside.hostname(), vector.did.hostname());
                    assert_eq!(inside.path_o(), vector.did.path_o());
                    assert_ne!(inside.root_self_hash(), vector.did.root_self_hash());
                }
                Some(ErrorCode::ResolutionPathMismatch) => {
                    assert_eq!(inside.hostname(), vector.did.hostname());
                    assert_eq!(inside.root_self_hash(), vector.did.root_self_hash());
                    assert_ne!(inside.path_o(), vector.did.path_o());
                }
                Some(ErrorCode::ResolutionHostMismatch) => {
                    assert_eq!(inside.path_o(), vector.did.path_o());
                    assert_eq!(inside.root_self_hash(), vector.did.root_self_hash());
                    assert_ne!(inside.hostname(), vector.did.hostname());
                    assert_eq!(inside.hostname(), FOREIGN_HOST);
                    assert_eq!(vector.did.hostname(), "example.com");
                }
                Some(ErrorCode::ResolutionPortMismatch) => {
                    assert_eq!(inside.hostname(), vector.did.hostname());
                    assert_eq!(inside.path_o(), vector.did.path_o());
                    assert_eq!(inside.root_self_hash(), vector.did.root_self_hash());
                    assert_eq!(inside.port_o(), Some(DEFAULT_FOREIGN_PORT));
                    assert_eq!(vector.did.port_o(), None);
                }
                other => panic!("{}: unexpected error code {other:?}", definition.name),
            }
        }
    }

    #[test]
    fn port_mismatch_differs_from_vdr_port_whether_or_not_vdr_has_port() {
        let no_port = TestVectorParams::baseline("example.com");
        let vector = port_mismatch(
            no_port,
            DeterministicRng::for_vector("resolution-unit", "port-none"),
        )
        .unwrap();
        assert_eq!(content_did(&vector).port_o(), Some(DEFAULT_FOREIGN_PORT));
        assert_eq!(vector.did.port_o(), None);

        let mut with_port = TestVectorParams::baseline("example.com");
        with_port.port_o = Some(3000);
        let vector = port_mismatch(
            with_port,
            DeterministicRng::for_vector("resolution-unit", "port-3000"),
        )
        .unwrap();
        assert_eq!(content_did(&vector).port_o(), Some(DEFAULT_FOREIGN_PORT));
        assert_eq!(vector.did.port_o(), Some(3000));

        let mut same_as_default = TestVectorParams::baseline("example.com");
        same_as_default.port_o = Some(DEFAULT_FOREIGN_PORT);
        let vector = port_mismatch(
            same_as_default,
            DeterministicRng::for_vector("resolution-unit", "port-12345"),
        )
        .unwrap();
        assert_eq!(content_did(&vector).port_o(), Some(ALTERNATE_FOREIGN_PORT));
        assert_eq!(vector.did.port_o(), Some(DEFAULT_FOREIGN_PORT));
    }

    #[test]
    fn path_vectors_respect_base_did_path_prefix() {
        let mut params = TestVectorParams::baseline("example.com");
        params.path_component_v = vec!["tv".to_owned(), "demo".to_owned()];

        let url_extra = path_url_has_extra(
            params.clone(),
            DeterministicRng::for_vector("resolution-unit", "path-url"),
        )
        .unwrap();
        assert_eq!(
            content_did(&url_extra).path_o().as_deref(),
            Some("tv:demo")
        );
        assert_eq!(url_extra.did.path_o().as_deref(), Some("tv:demo:extra"));

        let content_extra = path_content_has_extra(
            params,
            DeterministicRng::for_vector("resolution-unit", "path-content"),
        )
        .unwrap();
        assert_eq!(
            content_did(&content_extra).path_o().as_deref(),
            Some("tv:demo:extra")
        );
        assert_eq!(content_extra.did.path_o().as_deref(), Some("tv:demo"));
    }
}
