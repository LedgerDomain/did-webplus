import init, {
  Base,
  CreateDIDParameters,
  DID,
  DIDResolver,
  DeactivateDIDParameters,
  HashFunction,
  HTTPHeadersFor,
  HTTPOptions,
  HTTPSchemeOverride,
  IssueVPParameters,
  LocallyControlledVerificationMethodFilter,
  MBHashFunction,
  UpdateDIDParameters,
  Wallet,
  did_resolve,
  issue_vc_jwt,
  issue_vc_ldp,
  issue_vp_jwt,
  issue_vp_ldp,
  jwt_sign,
  jwt_verify,
  key_purpose_as_str,
  new_unsigned_credential,
  new_unsigned_presentation,
  verify_vc_jwt,
  verify_vc_ldp,
  verify_vp_jwt,
  verify_vp_ldp,
} from "./pkg/did_webplus_wasm.js";

const DEFAULTS = Object.freeze({
  walletDbName: "demo_wallet_db_v1",
  walletName: "did:webplus WASM demo",
  vdgHost: "vdg.did-webplus-wasm.test:8086",
  vdrCreateEndpoint: "http://vdr.did-webplus-wasm.test:8085",
  httpSchemeOverridePairs: "vdr.did-webplus-wasm.test=http,vdg.did-webplus-wasm.test=http",
  httpHeadersPairs: "",
});

const state = {
  ready: false,
  wallet: null,
  didResolver: null,
  dids: [],
  activeDidFq: "",
  walletBasedSigner: null,
};

const el = (() => {
  const byId = (id) => {
    const node = document.getElementById(id);
    if (!node) throw new Error(`Missing element #${id}`);
    return node;
  };
  return {
    appStatus: byId("appStatus"),
    walletDbName: byId("walletDbName"),
    walletName: byId("walletName"),
    httpSchemeOverride: byId("httpSchemeOverride"),
    httpHeadersFor: byId("httpHeadersFor"),
    applyHttpOptionsBtn: byId("applyHttpOptionsBtn"),
    httpOptionsStatus: byId("httpOptionsStatus"),

    vdrCreateEndpoint: byId("vdrCreateEndpoint"),
    createDidBtn: byId("createDidBtn"),
    refreshDidsBtn: byId("refreshDidsBtn"),
    activeDidSelect: byId("activeDidSelect"),
    updateDidBtn: byId("updateDidBtn"),
    deactivateDidBtn: byId("deactivateDidBtn"),
    walletOpsStatus: byId("walletOpsStatus"),

    vmsTbody: byId("vmsTbody"),

    didResolveInput: byId("didResolveInput"),
    didResolveBtn: byId("didResolveBtn"),
    didResolveOutput: byId("didResolveOutput"),
    didResolveStatus: byId("didResolveStatus"),
    copyDidResolutionBtn: byId("copyDidResolutionBtn"),

    signerKeyPurpose: byId("signerKeyPurpose"),
    signerKeyId: byId("signerKeyId"),
    createSignerBtn: byId("createSignerBtn"),
    clearSignerBtn: byId("clearSignerBtn"),
    signerStatus: byId("signerStatus"),

    signJwtBtn: byId("signJwtBtn"),
    issueVcJwtBtn: byId("issueVcJwtBtn"),
    issueVpJwtBtn: byId("issueVpJwtBtn"),
    issueVcLdpBtn: byId("issueVcLdpBtn"),
    issueVpLdpBtn: byId("issueVpLdpBtn"),
    signedArtifactOutput: byId("signedArtifactOutput"),
    copySignedArtifactBtn: byId("copySignedArtifactBtn"),
    signingStatus: byId("signingStatus"),

    jwtVerifyInput: byId("jwtVerifyInput"),
    jwtVerifyBtn: byId("jwtVerifyBtn"),
    jwtVerifyStatus: byId("jwtVerifyStatus"),
    jwtVerifyResult: byId("jwtVerifyResult"),

    vcJwtVerifyInput: byId("vcJwtVerifyInput"),
    vcJwtVerifyBtn: byId("vcJwtVerifyBtn"),
    vcJwtVerifyStatus: byId("vcJwtVerifyStatus"),
    vcJwtVerifyResult: byId("vcJwtVerifyResult"),

    vpJwtVerifyInput: byId("vpJwtVerifyInput"),
    vpJwtVerifyBtn: byId("vpJwtVerifyBtn"),
    vpJwtVerifyStatus: byId("vpJwtVerifyStatus"),
    vpJwtVerifyResult: byId("vpJwtVerifyResult"),

    vcLdpVerifyInput: byId("vcLdpVerifyInput"),
    vcLdpVerifyBtn: byId("vcLdpVerifyBtn"),
    vcLdpVerifyStatus: byId("vcLdpVerifyStatus"),

    vpLdpVerifyInput: byId("vpLdpVerifyInput"),
    vpLdpVerifyBtn: byId("vpLdpVerifyBtn"),
    vpLdpVerifyStatus: byId("vpLdpVerifyStatus"),

    confirmDeactivateDialog: byId("confirmDeactivateDialog"),
    confirmDeactivateBtn: byId("confirmDeactivateBtn"),

    jsonEditorDialog: byId("jsonEditorDialog"),
    jsonEditorTitle: byId("jsonEditorTitle"),
    jsonEditorTextarea: byId("jsonEditorTextarea"),
    jsonEditorStatus: byId("jsonEditorStatus"),
    jsonEditorOkBtn: byId("jsonEditorOkBtn"),
  };
})();

function setPill(pillEl, variant, text) {
  pillEl.dataset.variant = variant;
  pillEl.textContent = text;
}

function setInlineStatus(statusEl, variant, text) {
  statusEl.dataset.variant = variant;
  statusEl.textContent = text ?? "";
}

/** Reset verification UI when the user edits input so a prior Valid/Invalid result is not misleading. */
function resetVerifyRow(statusEl, resultEl) {
  setInlineStatus(statusEl, "warn", "Not checked");
  if (resultEl) resultEl.textContent = "";
}

function normalizeUrlInput(s) {
  return (s ?? "").trim();
}

function getActiveDidBase() {
  const fq = state.activeDidFq;
  if (!fq) return "";
  return fq.split("?")[0];
}

function clearSigner(reason) {
  state.walletBasedSigner = null;
  setInlineStatus(el.signerStatus, "idle", reason ?? "No signer");
  el.clearSignerBtn.disabled = true;
  updateSignButtons();
}

function updateSignButtons() {
  const enabled = Boolean(state.walletBasedSigner);
  el.signJwtBtn.disabled = !enabled;
  el.issueVcJwtBtn.disabled = !enabled;
  el.issueVpJwtBtn.disabled = !enabled;
  el.issueVcLdpBtn.disabled = !enabled;
  el.issueVpLdpBtn.disabled = !enabled;
}

function updateDidActionButtons() {
  const hasDid = Boolean(state.activeDidFq);
  el.updateDidBtn.disabled = !hasDid;
  el.deactivateDidBtn.disabled = !hasDid;
  el.createSignerBtn.disabled = !hasDid;
}

function setSignedArtifact(text) {
  el.signedArtifactOutput.value = text ?? "";
  el.copySignedArtifactBtn.disabled = !(text && text.length > 0);
}

async function copyTextToClipboard(text) {
  const s = text ?? "";
  if (!s) return;
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(s);
    return;
  }
  // Fallback
  const ta = document.createElement("textarea");
  ta.value = s;
  ta.style.position = "fixed";
  ta.style.left = "-10000px";
  document.body.appendChild(ta);
  ta.focus();
  ta.select();
  document.execCommand("copy");
  document.body.removeChild(ta);
}

function safeJsonParse(text) {
  const s = (text ?? "").trim();
  if (!s) throw new Error("JSON is empty");
  return JSON.parse(s);
}

function prettyJson(value) {
  return JSON.stringify(value, null, 2);
}

function toJsonCompatible(value) {
  if (value === null || value === undefined) return value;
  if (typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map((v) => toJsonCompatible(v));
  if (value instanceof Map) {
    const out = {};
    for (const [k, v] of value.entries()) {
      out[String(k)] = toJsonCompatible(v);
    }
    return out;
  }
  if (value instanceof Set) {
    return Array.from(value.values()).map((v) => toJsonCompatible(v));
  }
  const out = {};
  for (const [k, v] of Object.entries(value)) {
    out[k] = toJsonCompatible(v);
  }
  return out;
}

function stringifyForArtifact(value) {
  if (typeof value === "string") return value;
  return JSON.stringify(toJsonCompatible(value), null, 2);
}

function base64UrlToUint8Array(s) {
  const b64 = (s ?? "").replace(/-/g, "+").replace(/_/g, "/");
  const padLen = (4 - (b64.length % 4)) % 4;
  const padded = b64 + "=".repeat(padLen);
  const bin = atob(padded);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function decodeUtf8(bytes) {
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
}

function decodeJwtToObject(jwt) {
  const parts = String(jwt ?? "").trim().split(".");
  if (parts.length !== 3) throw new Error("JWT must have 3 dot-separated parts");
  const [h, p, sig] = parts;
  const headerText = decodeUtf8(base64UrlToUint8Array(h));
  const payloadText = decodeUtf8(base64UrlToUint8Array(p));
  const header = JSON.parse(headerText);
  const payload = JSON.parse(payloadText);
  return { header, payload, signature: sig };
}

function mbHashFunctionDefault() {
  return MBHashFunction.new(Base.Base64Url, HashFunction.Blake3);
}

function buildHttpOptionsFromInputs() {
  const schemePairs = normalizeUrlInput(el.httpSchemeOverride.value);
  const headersPairs = (el.httpHeadersFor.value ?? "").trim();

  const httpOptions = HTTPOptions.new();
  const schemeOverride = schemePairs
    ? HTTPSchemeOverride.parse_from_comma_separated_pairs(schemePairs)
    : HTTPSchemeOverride.new();

  httpOptions.set_http_scheme_override(schemeOverride);

  if (headersPairs) {
    const headersFor = HTTPHeadersFor.parse_from_semicolon_separated_pairs(headersPairs);
    httpOptions.set_http_headers_for(headersFor);
  } else {
    const headersFor = HTTPHeadersFor.new();
    httpOptions.set_http_headers_for(headersFor);
  }
  return httpOptions;
}

function getHttpOptions() {
  // IMPORTANT: wasm-bindgen methods take ownership of HTTPOptions (they call __destroy_into_raw()).
  // So HTTPOptions must be treated as single-use. Always construct a fresh one when calling into wasm.
  return buildHttpOptionsFromInputs();
}

function schemeOverridePairsContainHostScheme(pairs, hostname, scheme) {
  const s = (pairs ?? "").trim();
  if (!s) return false;
  // very small parser: comma-separated hostname=scheme
  return s
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean)
    .some((pair) => {
      const [h, sc] = pair.split("=").map((x) => (x ?? "").trim());
      return h === hostname && sc === scheme;
    });
}

function preflightHttpScheme({ targetUrl, purposeLabel }) {
  const u = new URL(targetUrl);
  const scheme = u.protocol.replace(":", "");
  if (scheme !== "http") return; // https is fine without overrides

  const pairs = normalizeUrlInput(el.httpSchemeOverride.value);
  const hasOverride = schemeOverridePairsContainHostScheme(pairs, u.hostname, "http");
  if (!hasOverride) {
    throw new Error(
      `${purposeLabel} uses an http:// URL (${u.hostname}), but Global HTTP scheme override does not include ` +
        `"${u.hostname}=http". Without it, the SDK defaults to https:// for non-localhost hosts and browser fetch will fail.\n\n` +
        `Fix: add "${u.hostname}=http" to Global HTTP scheme override and click Apply.`,
    );
  }
}

async function refreshControlledDids() {
  if (!state.wallet) return;
  const dids = await state.wallet.get_controlled_dids(null);
  state.dids = dids;

  const current = state.activeDidFq;
  el.activeDidSelect.innerHTML = `<option value="">(none)</option>`;
  for (const did of dids) {
    const opt = document.createElement("option");
    opt.value = did;
    opt.textContent = did;
    el.activeDidSelect.appendChild(opt);
  }
  if (current && dids.includes(current)) {
    el.activeDidSelect.value = current;
  } else {
    state.activeDidFq = "";
    el.activeDidSelect.value = "";
  }
  updateDidActionButtons();
}

function renderVmsEmpty(message) {
  el.vmsTbody.innerHTML = "";
  const tr = document.createElement("tr");
  const td = document.createElement("td");
  td.colSpan = 6;
  td.className = "muted";
  td.textContent = message;
  tr.appendChild(td);
  el.vmsTbody.appendChild(tr);
}

async function refreshLocallyControlledVerificationMethods() {
  if (!state.wallet || !state.activeDidFq) {
    renderVmsEmpty("Select an active DID to load keys.");
    return;
  }
  const didBase = getActiveDidBase();
  try {
    const did = DID.try_from_string(didBase);
    const filter = new LocallyControlledVerificationMethodFilter(did, null, null, null, 50);
    const records = await state.wallet.get_locally_controlled_verification_methods(filter);
    el.vmsTbody.innerHTML = "";
    if (!records || records.length === 0) {
      renderVmsEmpty("No locally controlled verification methods found for this DID.");
      return;
    }
    for (const rec of records) {
      const tr = document.createElement("tr");

      const purposes = (rec.key_purposes?.() ?? []).map((p) => key_purpose_as_str(p));
      const pubKey = rec.pub_key();

      const tdDid = document.createElement("td");
      // DID is a wasm-bound struct; display the active DID base to avoid relying on extra helpers.
      tdDid.textContent = didBase;
      const tdHash = document.createElement("td");
      tdHash.textContent = rec.query_self_hash();
      const tdVer = document.createElement("td");
      tdVer.textContent = String(rec.query_version_id());
      const tdPurp = document.createElement("td");
      tdPurp.textContent = purposes.join(", ");
      const tdPub = document.createElement("td");
      tdPub.textContent = pubKey;
      const tdCopy = document.createElement("td");
      const copyBtn = document.createElement("button");
      copyBtn.className = "btn btnSmall btnGhost";
      copyBtn.type = "button";
      copyBtn.textContent = "Copy";
      copyBtn.addEventListener("click", async () => {
        await copyTextToClipboard(pubKey);
      });
      tdCopy.appendChild(copyBtn);

      tr.append(tdDid, tdHash, tdVer, tdPurp, tdPub, tdCopy);
      el.vmsTbody.appendChild(tr);
    }
  } catch (e) {
    console.error(e);
    renderVmsEmpty(`Failed to load verification methods: ${String(e)}`);
  }
}

function openJsonEditor({ title, defaultValue }) {
  el.jsonEditorTitle.textContent = title;
  el.jsonEditorTextarea.value = defaultValue ?? "";
  setInlineStatus(el.jsonEditorStatus, "idle", "");
  el.jsonEditorDialog.showModal();
  el.jsonEditorTextarea.focus();
}

function waitForJsonEditorOk() {
  return new Promise((resolve) => {
    const onClose = () => {
      el.jsonEditorDialog.removeEventListener("close", onClose);
      const returnValue = el.jsonEditorDialog.returnValue;
      if (returnValue !== "ok") {
        resolve({ ok: false, text: "" });
      } else {
        resolve({ ok: true, text: el.jsonEditorTextarea.value });
      }
    };
    el.jsonEditorDialog.addEventListener("close", onClose);
  });
}

async function initApp() {
  setPill(el.appStatus, "warn", "Loading…");
  el.walletDbName.textContent = DEFAULTS.walletDbName;
  el.walletName.textContent = DEFAULTS.walletName;
  el.vdrCreateEndpoint.value = DEFAULTS.vdrCreateEndpoint;
  el.httpSchemeOverride.value = DEFAULTS.httpSchemeOverridePairs;
  el.httpHeadersFor.value = DEFAULTS.httpHeadersPairs;
  el.didResolveInput.value = "";

  await init();

  setInlineStatus(el.httpOptionsStatus, "ok", "Applied (defaults)");

  state.wallet = await Wallet.create(DEFAULTS.walletDbName, DEFAULTS.walletName, DEFAULTS.vdgHost);
  state.didResolver = DIDResolver.new_thin(DEFAULTS.vdgHost, getHttpOptions());

  state.ready = true;
  setPill(el.appStatus, "ok", "Ready");

  await refreshControlledDids();
  renderVmsEmpty("Select an active DID to load keys.");
  updateDidActionButtons();
  clearSigner("No signer");
  setSignedArtifact("");
  setInlineStatus(el.walletOpsStatus, "idle", "");
}

async function handleApplyHttpOptions() {
  try {
    // Recreate resolver to pick up new global HTTPOptions
    state.didResolver = DIDResolver.new_thin(DEFAULTS.vdgHost, getHttpOptions());
    setInlineStatus(el.httpOptionsStatus, "ok", "Applied");
  } catch (e) {
    console.error(e);
    setInlineStatus(el.httpOptionsStatus, "bad", String(e));
  }
}

function ensureHttpOptionsUpToDate() {
  // Treat the global HTTP settings inputs as the source of truth.
  // This prevents subtle issues where the user edits inputs but forgets to click Apply.
  try {
    state.didResolver = DIDResolver.new_thin(DEFAULTS.vdgHost, getHttpOptions());
    setInlineStatus(el.httpOptionsStatus, "ok", "Applied");
  } catch (e) {
    // Keep old options; the caller will hit a better error at the point of use.
    console.error(e);
  }
}

async function handleCreateDid() {
  if (!state.wallet) return;
  setInlineStatus(el.walletOpsStatus, "warn", "Creating DID…");
  try {
    ensureHttpOptionsUpToDate();
    const endpoint = normalizeUrlInput(el.vdrCreateEndpoint.value);
    if (!endpoint) throw new Error("VDR create endpoint is empty");
    // Validate URL format lightly
    preflightHttpScheme({ targetUrl: endpoint, purposeLabel: "Create DID" });

    // wasm-bindgen objects are move-only on JS side; each arg needs its own instance.
    const mbForDid = mbHashFunctionDefault();
    const mbForUpdateKey = mbHashFunctionDefault();
    const params = CreateDIDParameters.new(endpoint, mbForDid, mbForUpdateKey);
    const didFq = await state.wallet.create_did(params, getHttpOptions());
    setInlineStatus(el.walletOpsStatus, "ok", "DID created");
    await refreshControlledDids();
    state.activeDidFq = didFq;
    el.activeDidSelect.value = didFq;
    updateDidActionButtons();
    clearSigner("Signer cleared (DID changed)");
    await refreshLocallyControlledVerificationMethods();
  } catch (e) {
    console.error(e);
    setInlineStatus(el.walletOpsStatus, "bad", String(e));
  }
}

async function handleUpdateDid() {
  if (!state.wallet || !state.activeDidFq) return;
  setInlineStatus(el.walletOpsStatus, "warn", "Updating DID…");
  try {
    ensureHttpOptionsUpToDate();
    const didBase = getActiveDidBase();
    const did = DID.try_from_string(didBase);
    const mbUpdateKey = mbHashFunctionDefault();
    const params = UpdateDIDParameters.new(did, null, mbUpdateKey);
    const didFq = await state.wallet.update_did(params, getHttpOptions());
    setInlineStatus(el.walletOpsStatus, "ok", "DID updated");
    await refreshControlledDids();
    state.activeDidFq = didFq;
    el.activeDidSelect.value = didFq;
    updateDidActionButtons();
    clearSigner("Signer cleared (DID updated)");
    await refreshLocallyControlledVerificationMethods();
  } catch (e) {
    console.error(e);
    setInlineStatus(el.walletOpsStatus, "bad", String(e));
  }
}

async function handleDeactivateDidConfirmed() {
  if (!state.wallet || !state.activeDidFq) return;
  setInlineStatus(el.walletOpsStatus, "warn", "Deactivating DID…");
  try {
    ensureHttpOptionsUpToDate();
    const didBase = getActiveDidBase();
    const did = DID.try_from_string(didBase);
    const params = DeactivateDIDParameters.new(did, null);
    const didFq = await state.wallet.deactivate_did(params, getHttpOptions());
    setInlineStatus(el.walletOpsStatus, "ok", "DID deactivated");
    await refreshControlledDids();
    state.activeDidFq = didFq;
    el.activeDidSelect.value = didFq;
    updateDidActionButtons();
    clearSigner("Signer cleared (DID deactivated)");
    await refreshLocallyControlledVerificationMethods();
  } catch (e) {
    console.error(e);
    setInlineStatus(el.walletOpsStatus, "bad", String(e));
  }
}

async function handleResolveDid() {
  if (!state.didResolver) return;
  setInlineStatus(el.didResolveStatus, "warn", "Resolving…");
  el.didResolveOutput.value = "";
  el.copyDidResolutionBtn.disabled = true;
  try {
    ensureHttpOptionsUpToDate();
    const q = (el.didResolveInput.value ?? "").trim();
    if (!q) throw new Error("DID query is empty");
    const doc = await did_resolve(q, state.didResolver);
    el.didResolveOutput.value = doc;
    el.copyDidResolutionBtn.disabled = !doc;
    setInlineStatus(el.didResolveStatus, "ok", "Resolved");
  } catch (e) {
    console.error(e);
    setInlineStatus(el.didResolveStatus, "bad", String(e));
  }
}

async function handleCreateSigner() {
  if (!state.wallet || !state.activeDidFq) return;
  try {
    ensureHttpOptionsUpToDate();
    const didBase = getActiveDidBase();
    const purpose = el.signerKeyPurpose.value;
    const keyId = (el.signerKeyId.value ?? "").trim();
    setInlineStatus(el.signerStatus, "warn", "Creating signer…");
    state.walletBasedSigner = await state.wallet.new_wallet_based_signer(
      didBase,
      purpose,
      keyId ? keyId : null,
      getHttpOptions(),
    );
    setInlineStatus(el.signerStatus, "ok", "Signer ready");
    el.clearSignerBtn.disabled = false;
    updateSignButtons();
  } catch (e) {
    console.error(e);
    state.walletBasedSigner = null;
    setInlineStatus(el.signerStatus, "bad", String(e));
    el.clearSignerBtn.disabled = true;
    updateSignButtons();
  }
}

async function handleSignJwt() {
  if (!state.walletBasedSigner) return;
  const defaultClaims = prettyJson({
    iss: getActiveDidBase() || "did:webplus:example",
    sub: "https://example.org/subject",
    aud: "https://example.org/audience",
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
    name: "Grunty McParty",
    email: "g@mc-p.org",
  });
  openJsonEditor({ title: "JWT claims (JSON)", defaultValue: defaultClaims });
  const { ok, text } = await waitForJsonEditorOk();
  if (!ok) return;
  try {
    setInlineStatus(el.signingStatus, "warn", "Signing JWT…");
    const claims = safeJsonParse(text);
    const jwt = await jwt_sign(claims, state.walletBasedSigner);
    setSignedArtifact(jwt);
    setInlineStatus(el.signingStatus, "ok", "JWT signed");
  } catch (e) {
    console.error(e);
    setInlineStatus(el.signingStatus, "bad", String(e));
  }
}

async function handleIssueVcJwtOrLdp({ format }) {
  if (!state.walletBasedSigner) return;
  const unsigned = {
    additionalContexts: null,
    credentialId: "https://example.org/#CredentialId",
    issuanceDate: new Date(),
    expirationDate: new Date(Date.now() + 365 * 24 * 3600 * 1000),
    credentialSubject: {
      id: "https://example.org/#CredentialSubjectId",
      "https://example.org/#name": "Grunty McParty",
      "https://example.org/#email": "g@mc-p.org",
    },
  };
  const defaultValue = prettyJson(unsigned);
  openJsonEditor({
    title: `Unsigned VC input (${format.toUpperCase()})`,
    defaultValue,
  });
  const { ok, text } = await waitForJsonEditorOk();
  if (!ok) return;
  try {
    setInlineStatus(el.signingStatus, "warn", `Issuing VC (${format.toUpperCase()})…`);
    const input = safeJsonParse(text);
    const unsignedVc = new_unsigned_credential(
      input.additionalContexts ?? null,
      String(input.credentialId),
      new Date(input.issuanceDate),
      new Date(input.expirationDate),
      input.credentialSubject ?? {},
    );
    if (format === "jwt") {
      const vcJwt = await issue_vc_jwt(unsignedVc, state.walletBasedSigner);
      setSignedArtifact(vcJwt);
    } else {
      const vcLdp = await issue_vc_ldp(unsignedVc, state.walletBasedSigner, state.didResolver);
      setSignedArtifact(stringifyForArtifact(vcLdp));
    }
    setInlineStatus(el.signingStatus, "ok", `VC issued (${format.toUpperCase()})`);
  } catch (e) {
    console.error(e);
    setInlineStatus(el.signingStatus, "bad", String(e));
  }
}

async function handleIssueVpJwtOrLdp({ format }) {
  if (!state.walletBasedSigner) return;
  const inputDefaultBase = {
    additionalContexts: null,
    presentationId: "https://example.org/#PresentationId",
    verifiableCredentials: [],
    issueVpParameters: {
      challenge: "challenge",
      domains: ["example.org"],
      nonce: "nonce",
    },
  };
  // LDP VPs must not carry issuanceDate / expirationDate on the presentation; JWT VP may.
  const inputDefault =
    format === "ldp"
      ? inputDefaultBase
      : {
          ...inputDefaultBase,
          issuanceDate: new Date(),
          expirationDate: new Date(Date.now() + 3600 * 1000),
        };
  openJsonEditor({
    title: `Unsigned VP input (${format.toUpperCase()})`,
    defaultValue: prettyJson(inputDefault),
  });
  const { ok, text } = await waitForJsonEditorOk();
  if (!ok) return;
  try {
    setInlineStatus(el.signingStatus, "warn", `Issuing VP (${format.toUpperCase()})…`);
    const input = safeJsonParse(text);
    const unsignedVp = new_unsigned_presentation(
      input.additionalContexts ?? null,
      String(input.presentationId),
      input.issuanceDate ? new Date(input.issuanceDate) : null,
      input.expirationDate ? new Date(input.expirationDate) : null,
      (input.verifiableCredentials ?? []).map((x) => x),
    );
    const p = input.issueVpParameters ?? {};
    const issueParams = IssueVPParameters.new(
      p.challenge ?? null,
      p.domains ?? null,
      p.nonce ?? null,
    );
    if (format === "jwt") {
      const vpJwt = await issue_vp_jwt(unsignedVp, issueParams, state.walletBasedSigner);
      setSignedArtifact(vpJwt);
    } else {
      const vpLdp = await issue_vp_ldp(
        unsignedVp,
        issueParams,
        state.walletBasedSigner,
        state.didResolver,
      );
      setSignedArtifact(stringifyForArtifact(vpLdp));
    }
    setInlineStatus(el.signingStatus, "ok", `VP issued (${format.toUpperCase()})`);
  } catch (e) {
    console.error(e);
    setInlineStatus(el.signingStatus, "bad", String(e));
  }
}

async function handleJwtVerify() {
  setInlineStatus(el.jwtVerifyStatus, "warn", "Checking…");
  el.jwtVerifyResult.textContent = "";
  try {
    const jwt = (el.jwtVerifyInput.value ?? "").trim();
    if (!jwt) throw new Error("JWT input is empty");
    await jwt_verify(jwt, state.didResolver);
    el.jwtVerifyResult.textContent = prettyJson(decodeJwtToObject(jwt));
    setInlineStatus(el.jwtVerifyStatus, "ok", "Valid");
  } catch (e) {
    console.error(e);
    setInlineStatus(el.jwtVerifyStatus, "bad", `Invalid: ${String(e)}`);
  }
}

async function handleSimpleVerify({ kind }) {
  const map = {
    vcJwt: { inputEl: el.vcJwtVerifyInput, statusEl: el.vcJwtVerifyStatus, resultEl: el.vcJwtVerifyResult, fn: verify_vc_jwt, json: false },
    vpJwt: { inputEl: el.vpJwtVerifyInput, statusEl: el.vpJwtVerifyStatus, resultEl: el.vpJwtVerifyResult, fn: verify_vp_jwt, json: false },
    vcLdp: { inputEl: el.vcLdpVerifyInput, statusEl: el.vcLdpVerifyStatus, fn: verify_vc_ldp, json: true },
    vpLdp: { inputEl: el.vpLdpVerifyInput, statusEl: el.vpLdpVerifyStatus, fn: verify_vp_ldp, json: true },
  };
  const cfg = map[kind];
  if (!cfg) return;
  setInlineStatus(cfg.statusEl, "warn", "Checking…");
  if (cfg.resultEl) cfg.resultEl.textContent = "";
  try {
    const raw = (cfg.inputEl.value ?? "").trim();
    if (!raw) throw new Error("Input is empty");
    if (cfg.json) {
      const value = safeJsonParse(raw);
      await cfg.fn(value, state.didResolver);
    } else {
      await cfg.fn(raw, state.didResolver);
    }
    if (cfg.resultEl) cfg.resultEl.textContent = prettyJson(decodeJwtToObject(raw));
    setInlineStatus(cfg.statusEl, "ok", "Valid");
  } catch (e) {
    console.error(e);
    setInlineStatus(cfg.statusEl, "bad", `Invalid: ${String(e)}`);
  }
}

function wireEvents() {
  el.applyHttpOptionsBtn.addEventListener("click", handleApplyHttpOptions);

  el.refreshDidsBtn.addEventListener("click", async () => {
    setInlineStatus(el.walletOpsStatus, "warn", "Refreshing…");
    try {
      await refreshControlledDids();
      await refreshLocallyControlledVerificationMethods();
      setInlineStatus(el.walletOpsStatus, "ok", "Refreshed");
    } catch (e) {
      console.error(e);
      setInlineStatus(el.walletOpsStatus, "bad", String(e));
    }
  });

  el.createDidBtn.addEventListener("click", handleCreateDid);
  el.updateDidBtn.addEventListener("click", handleUpdateDid);

  el.deactivateDidBtn.addEventListener("click", () => {
    if (!state.activeDidFq) return;
    el.confirmDeactivateDialog.showModal();
  });
  el.confirmDeactivateDialog.addEventListener("close", async () => {
    if (el.confirmDeactivateDialog.returnValue === "confirm") {
      await handleDeactivateDidConfirmed();
    }
  });

  el.activeDidSelect.addEventListener("change", async () => {
    state.activeDidFq = el.activeDidSelect.value;
    updateDidActionButtons();
    clearSigner("Signer cleared (active DID changed)");
    await refreshLocallyControlledVerificationMethods();
  });

  el.copyDidResolutionBtn.addEventListener("click", async () => {
    await copyTextToClipboard(el.didResolveOutput.value);
  });
  el.didResolveBtn.addEventListener("click", handleResolveDid);

  el.createSignerBtn.addEventListener("click", handleCreateSigner);
  el.clearSignerBtn.addEventListener("click", () => clearSigner("No signer"));

  el.copySignedArtifactBtn.addEventListener("click", async () => {
    await copyTextToClipboard(el.signedArtifactOutput.value);
  });

  el.signJwtBtn.addEventListener("click", handleSignJwt);
  el.issueVcJwtBtn.addEventListener("click", () => handleIssueVcJwtOrLdp({ format: "jwt" }));
  el.issueVcLdpBtn.addEventListener("click", () => handleIssueVcJwtOrLdp({ format: "ldp" }));
  el.issueVpJwtBtn.addEventListener("click", () => handleIssueVpJwtOrLdp({ format: "jwt" }));
  el.issueVpLdpBtn.addEventListener("click", () => handleIssueVpJwtOrLdp({ format: "ldp" }));

  el.jwtVerifyBtn.addEventListener("click", handleJwtVerify);
  el.vcJwtVerifyBtn.addEventListener("click", () => handleSimpleVerify({ kind: "vcJwt" }));
  el.vpJwtVerifyBtn.addEventListener("click", () => handleSimpleVerify({ kind: "vpJwt" }));
  el.vcLdpVerifyBtn.addEventListener("click", () => handleSimpleVerify({ kind: "vcLdp" }));
  el.vpLdpVerifyBtn.addEventListener("click", () => handleSimpleVerify({ kind: "vpLdp" }));

  el.jwtVerifyInput.addEventListener("input", () =>
    resetVerifyRow(el.jwtVerifyStatus, el.jwtVerifyResult),
  );
  el.vcJwtVerifyInput.addEventListener("input", () =>
    resetVerifyRow(el.vcJwtVerifyStatus, el.vcJwtVerifyResult),
  );
  el.vpJwtVerifyInput.addEventListener("input", () =>
    resetVerifyRow(el.vpJwtVerifyStatus, el.vpJwtVerifyResult),
  );
  el.vcLdpVerifyInput.addEventListener("input", () => resetVerifyRow(el.vcLdpVerifyStatus));
  el.vpLdpVerifyInput.addEventListener("input", () => resetVerifyRow(el.vpLdpVerifyStatus));
}

wireEvents();
initApp().catch((e) => {
  console.error(e);
  setPill(el.appStatus, "bad", `Failed: ${String(e)}`);
});

