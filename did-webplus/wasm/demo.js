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
  activeWalletUuid: "",
  walletRecords: [],
  didResolver: null,
  dids: [],
  activeDidFq: "",
  didMutationInFlight: false,
  didMutationCooldownUntilMs: 0,
};

const DID_MUTATION_COOLDOWN_MS = 500;

function startDidMutationCooldown() {
  state.didMutationCooldownUntilMs = Date.now() + DID_MUTATION_COOLDOWN_MS;
  updateWalletDependentUi();
  setTimeout(() => {
    updateWalletDependentUi();
  }, DID_MUTATION_COOLDOWN_MS + 30);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchDidWithRetry({ didBase, attempts, delayMs }) {
  let lastErr = null;
  for (let i = 0; i < attempts; i++) {
    try {
      await state.wallet.fetch_did(didBase, getHttpOptions());
      return;
    } catch (e) {
      lastErr = e;
      if (i + 1 < attempts) await sleep(delayMs);
    }
  }
  throw lastErr ?? new Error("fetch_did failed");
}

const el = (() => {
  const byId = (id) => {
    const node = document.getElementById(id);
    if (!node) throw new Error(`Missing element #${id}`);
    return node;
  };
  return {
    appStatus: byId("appStatus"),
    walletsCard: byId("walletsCard"),
    activeWalletCard: byId("activeWalletCard"),
    activeDidCard: byId("activeDidCard"),
    walletDbName: byId("walletDbName"),
    activeDidSummaryVersionId: byId("activeDidSummaryVersionId"),
    activeWalletHeaderNameBtn: byId("activeWalletHeaderNameBtn"),
    activeWalletHeaderUuidBtn: byId("activeWalletHeaderUuidBtn"),
    activeDidHeaderDidBtn: byId("activeDidHeaderDidBtn"),
    activeDidSummarySelfHashBtn: byId("activeDidSummarySelfHashBtn"),
    refreshWalletsBtn: byId("refreshWalletsBtn"),
    createWalletBtn: byId("createWalletBtn"),
    newWalletName: byId("newWalletName"),
    walletsStatus: byId("walletsStatus"),
    walletsTbody: byId("walletsTbody"),
    httpSchemeOverride: byId("httpSchemeOverride"),
    httpHeadersFor: byId("httpHeadersFor"),
    applyHttpOptionsBtn: byId("applyHttpOptionsBtn"),
    httpOptionsStatus: byId("httpOptionsStatus"),

    vdrCreateEndpoint: byId("vdrCreateEndpoint"),
    createDidBtn: byId("createDidBtn"),
    refreshDidsBtn: byId("refreshDidsBtn"),
    activeDidsTbody: byId("activeDidsTbody"),
    updateDidBtn: byId("updateDidBtn"),
    deactivateDidBtn: byId("deactivateDidBtn"),
    walletOpsStatus: byId("walletOpsStatus"),

    vmsTbody: byId("vmsTbody"),

    didResolveInput: byId("didResolveInput"),
    didResolveBtn: byId("didResolveBtn"),
    didResolveOutput: byId("didResolveOutput"),
    didResolveStatus: byId("didResolveStatus"),
    copyDidResolutionBtn: byId("copyDidResolutionBtn"),
    signingOffline: byId("signingOffline"),

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
    jsonEditorSubtitle: byId("jsonEditorSubtitle"),
    jsonEditorExtra: byId("jsonEditorExtra"),
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

function updateSignButtons() {
  const enabled = Boolean(state.wallet) && Boolean(state.activeDidFq);
  el.signJwtBtn.disabled = !enabled;
  el.issueVcJwtBtn.disabled = !enabled;
  el.issueVpJwtBtn.disabled = !enabled;
  el.issueVcLdpBtn.disabled = !enabled;
  el.issueVpLdpBtn.disabled = !enabled;
}

function updateWalletDependentUi() {
  const hasWallet = Boolean(state.wallet);
  const hasDid = hasWallet && Boolean(state.activeDidFq);
  const cooldownActive = Date.now() < state.didMutationCooldownUntilMs;
  const allowDidMutations = hasDid && !state.didMutationInFlight && !cooldownActive;

  el.activeWalletCard.classList.toggle("hidden", !hasWallet);
  el.activeDidCard.classList.toggle("hidden", !hasDid);

  el.createDidBtn.disabled = !hasWallet;
  el.refreshDidsBtn.disabled = !hasWallet;
  el.updateDidBtn.disabled = !allowDidMutations;
  el.deactivateDidBtn.disabled = !allowDidMutations;
  updateSignButtons();
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

async function copyWithFeedback(buttonEl, text) {
  const s = String(text ?? "");
  if (!s) return;
  await copyTextToClipboard(s);
  if (!buttonEl) return;

  const prevText = buttonEl.textContent;
  const prevTitle = buttonEl.title;
  buttonEl.textContent = "Copied";
  buttonEl.title = "Copied to clipboard";
  buttonEl.disabled = true;
  setTimeout(() => {
    buttonEl.textContent = prevText;
    buttonEl.title = prevTitle || "Copy to clipboard";
    buttonEl.disabled = false;
  }, 900);
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

function parseDidFq(didFq) {
  const fq = String(didFq ?? "").trim();
  const [base, query] = fq.split("?");
  const params = new URLSearchParams(query ?? "");
  return {
    fq,
    base: base ?? "",
    selfHash: params.get("selfHash") ?? "",
    versionId: params.get("versionId") ?? "",
  };
}

function setActiveDidSummary() {
  if (!state.activeDidFq) {
    el.activeDidSummaryVersionId.textContent = "—";
    el.activeDidHeaderDidBtn.textContent = "—";
    el.activeDidHeaderDidBtn.disabled = true;
    el.activeDidSummarySelfHashBtn.textContent = "—";
    el.activeDidSummarySelfHashBtn.disabled = true;
    return;
  }
  const { base, selfHash, versionId } = parseDidFq(state.activeDidFq);
  el.activeDidSummaryVersionId.textContent = versionId || "—";
  el.activeDidHeaderDidBtn.textContent = base || "—";
  el.activeDidHeaderDidBtn.disabled = !base;
  el.activeDidSummarySelfHashBtn.textContent = selfHash || "—";
  el.activeDidSummarySelfHashBtn.disabled = !selfHash;
}

function renderActiveDidsEmpty(message) {
  el.activeDidsTbody.innerHTML = "";
  const tr = document.createElement("tr");
  const td = document.createElement("td");
  td.colSpan = 5;
  td.className = "muted";
  td.textContent = message;
  tr.appendChild(td);
  el.activeDidsTbody.appendChild(tr);
}

async function refreshControlledDids() {
  if (!state.wallet) {
    state.dids = [];
    state.activeDidFq = "";
    setActiveDidSummary();
    renderActiveDidsEmpty("Select an active wallet to load DIDs.");
    updateWalletDependentUi();
    return;
  }
  const dids = await state.wallet.get_controlled_dids(null);
  state.dids = dids;

  const current = state.activeDidFq;
  if (current && dids.includes(current)) {
    // keep
  } else {
    state.activeDidFq = "";
  }
  setActiveDidSummary();

  el.activeDidsTbody.innerHTML = "";
  if (!dids || dids.length === 0) {
    renderActiveDidsEmpty("No controlled DIDs found for this wallet.");
    updateWalletDependentUi();
    return;
  }

  for (const didFq of dids) {
    const { base, selfHash, versionId } = parseDidFq(didFq);

    const tr = document.createElement("tr");

    const tdActive = document.createElement("td");
    const radio = document.createElement("input");
    radio.type = "radio";
    radio.name = "activeDidFq";
    radio.value = didFq;
    radio.checked = didFq === state.activeDidFq;
    radio.addEventListener("change", async () => {
      state.activeDidFq = didFq;
      setActiveDidSummary();
      updateWalletDependentUi();
      await refreshLocallyControlledVerificationMethods();
    });
    tdActive.appendChild(radio);

    const tdDid = document.createElement("td");
    tdDid.className = "mono";
    tdDid.textContent = base;

    const tdHash = document.createElement("td");
    tdHash.className = "mono";
    tdHash.textContent = selfHash || "—";

    const tdVer = document.createElement("td");
    tdVer.className = "mono";
    tdVer.textContent = versionId || "—";

    const tdCopy = document.createElement("td");
    const copyBtn = document.createElement("button");
    copyBtn.className = "btn btnSmall btnGhost";
    copyBtn.type = "button";
    copyBtn.textContent = "Copy";
    copyBtn.addEventListener("click", async () => {
      await copyTextToClipboard(base);
    });
    tdCopy.appendChild(copyBtn);

    tr.append(tdActive, tdDid, tdHash, tdVer, tdCopy);
    el.activeDidsTbody.appendChild(tr);
  }

  updateWalletDependentUi();
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

function formatWalletRecordTime(s) {
  const raw = String(s ?? "").trim();
  if (!raw) return "";
  const d = new Date(raw);
  if (Number.isNaN(d.getTime())) return raw;
  return d.toLocaleString();
}

function getWalletRecordName(rec) {
  try {
    if (typeof rec.wallet_name_o === "function") return rec.wallet_name_o() ?? "";
  } catch {}
  try {
    if (typeof rec.wallet_name === "function") return rec.wallet_name() ?? "";
  } catch {}
  return "";
}

function isWalletRecordDeleted(rec) {
  try {
    const v = rec.deleted_at_o?.();
    return Boolean(v);
  } catch {
    return false;
  }
}

function setActiveWalletSummary() {
  if (!state.activeWalletUuid) {
    el.activeWalletHeaderNameBtn.textContent = "—";
    el.activeWalletHeaderNameBtn.disabled = true;
    el.activeWalletHeaderUuidBtn.textContent = "—";
    el.activeWalletHeaderUuidBtn.disabled = true;
    return;
  }
  const rec =
    state.walletRecords.find((r) => (r.wallet_uuid?.() ?? "") === state.activeWalletUuid) ?? null;
  const name = rec ? getWalletRecordName(rec) : "";
  el.activeWalletHeaderNameBtn.textContent = name || "—";
  el.activeWalletHeaderNameBtn.disabled = !name;
  el.activeWalletHeaderUuidBtn.textContent = state.activeWalletUuid;
  el.activeWalletHeaderUuidBtn.disabled = false;
}

function renderWalletsEmpty(message) {
  el.walletsTbody.innerHTML = "";
  const tr = document.createElement("tr");
  const td = document.createElement("td");
  td.colSpan = 4;
  td.className = "muted";
  td.textContent = message;
  tr.appendChild(td);
  el.walletsTbody.appendChild(tr);
}

async function clearActiveWallet({ reason }) {
  state.wallet = null;
  state.activeWalletUuid = "";
  setActiveWalletSummary();
  state.activeDidFq = "";
  setActiveDidSummary();
  renderActiveDidsEmpty("Select an active wallet to load DIDs.");
  renderVmsEmpty("Select an active DID to load keys.");
  setSignedArtifact("");
  setInlineStatus(el.walletOpsStatus, "idle", reason ?? "");
  updateWalletDependentUi();
}

async function openWalletByUuid(walletUuid) {
  const uuid = String(walletUuid ?? "").trim();
  if (!uuid) {
    await clearActiveWallet({ reason: "" });
    return;
  }
  state.wallet = await Wallet.open(DEFAULTS.walletDbName, uuid, DEFAULTS.vdgHost);
  state.activeWalletUuid = uuid;
  setActiveWalletSummary();
  await refreshWalletRecords({ autoSelectSingle: false });

  // Active DID is wallet-specific.
  state.activeDidFq = "";
  setActiveDidSummary();
  await refreshControlledDids();
  await refreshLocallyControlledVerificationMethods();
  setSignedArtifact("");
  updateWalletDependentUi();
}

function pickNewestWalletUuid(records) {
  let best = null;
  let bestT = -Infinity;
  for (const rec of records) {
    const uuid = rec.wallet_uuid?.() ?? "";
    const createdAt = rec.created_at?.() ?? "";
    const t = new Date(createdAt).getTime();
    if (!uuid) continue;
    const tt = Number.isNaN(t) ? -Infinity : t;
    if (best === null || tt > bestT) {
      best = uuid;
      bestT = tt;
    }
  }
  return best ?? "";
}

async function refreshWalletRecords({ autoSelectSingle }) {
  setInlineStatus(el.walletsStatus, "warn", "Loading…");
  try {
    const records = await Wallet.get_wallet_records(DEFAULTS.walletDbName);
    const active = state.activeWalletUuid;
    const visible = (records ?? []).filter((r) => !isWalletRecordDeleted(r));
    state.walletRecords = visible;

    el.walletsTbody.innerHTML = "";
    if (!visible || visible.length === 0) {
      renderWalletsEmpty("No wallets found. Create a new wallet to begin.");
      await clearActiveWallet({ reason: "" });
      setInlineStatus(el.walletsStatus, "ok", "Loaded (0)");
      return;
    }

    for (const rec of visible) {
      const uuid = rec.wallet_uuid();
      const name = getWalletRecordName(rec);
      const createdAt = rec.created_at?.() ?? "";

      const tr = document.createElement("tr");

      const tdActive = document.createElement("td");
      const radio = document.createElement("input");
      radio.type = "radio";
      radio.name = "activeWalletUuid";
      radio.value = uuid;
      radio.checked = uuid === active;
      radio.addEventListener("change", async () => {
        setInlineStatus(el.walletOpsStatus, "idle", "");
        await openWalletByUuid(uuid);
      });
      tdActive.appendChild(radio);

      const tdUuid = document.createElement("td");
      tdUuid.className = "mono";
      tdUuid.textContent = uuid;

      const tdName = document.createElement("td");
      tdName.textContent = name || "—";

      const tdCreated = document.createElement("td");
      tdCreated.className = "mono";
      tdCreated.textContent = formatWalletRecordTime(createdAt);

      tr.append(tdActive, tdUuid, tdName, tdCreated);
      el.walletsTbody.appendChild(tr);
    }

    // If active wallet disappeared, clear it.
    if (active && !visible.some((r) => r.wallet_uuid() === active)) {
      await clearActiveWallet({ reason: "" });
    }

    // Auto-select when exactly one record exists and none is active.
    if (autoSelectSingle && !state.activeWalletUuid && visible.length === 1) {
      await openWalletByUuid(visible[0].wallet_uuid());
    }

    setActiveWalletSummary();
    setInlineStatus(el.walletsStatus, "ok", `Loaded (${visible.length})`);
  } catch (e) {
    console.error(e);
    renderWalletsEmpty(`Failed to load wallets: ${String(e)}`);
    setInlineStatus(el.walletsStatus, "bad", String(e));
    await clearActiveWallet({ reason: "" });
  }
}

function openJsonEditor({ title, defaultValue }) {
  el.jsonEditorTitle.textContent = title;
  el.jsonEditorSubtitle.textContent = "";
  el.jsonEditorExtra.innerHTML = "";
  el.jsonEditorTextarea.value = defaultValue ?? "";
  setInlineStatus(el.jsonEditorStatus, "idle", "");
  el.jsonEditorDialog.showModal();
  el.jsonEditorTextarea.focus();
}

function openJsonEditorV2({ title, subtitle, defaultValue, extraEl }) {
  el.jsonEditorTitle.textContent = title ?? "";
  el.jsonEditorSubtitle.textContent = subtitle ?? "";
  el.jsonEditorExtra.innerHTML = "";
  if (extraEl) el.jsonEditorExtra.appendChild(extraEl);
  el.jsonEditorTextarea.value = defaultValue ?? "";
  setInlineStatus(el.jsonEditorStatus, "idle", "");
  el.jsonEditorDialog.showModal();
  el.jsonEditorTextarea.focus();
}

function buildSigningContextEl() {
  const wrap = document.createElement("div");
  wrap.className = "formRow";

  const label = document.createElement("div");
  label.className = "label";
  label.textContent = "Sign using";

  const row = document.createElement("div");
  row.className = "row";

  const walletRec =
    state.walletRecords.find((r) => (r.wallet_uuid?.() ?? "") === state.activeWalletUuid) ?? null;
  const walletName = walletRec ? getWalletRecordName(walletRec) : "";
  const didBase = getActiveDidBase();
  const didText = didBase || "—";

  const walletNameBtn = document.createElement("button");
  walletNameBtn.type = "button";
  walletNameBtn.className = "btnPill mono";
  walletNameBtn.title = "Copy to clipboard";
  walletNameBtn.textContent = `Wallet name: ${walletName || "—"}`;
  walletNameBtn.disabled = !walletName;
  walletNameBtn.addEventListener("click", async () => {
    if (!walletName) return;
    await copyWithFeedback(walletNameBtn, walletName);
  });

  const walletBtn = document.createElement("button");
  walletBtn.type = "button";
  walletBtn.className = "btnPill mono";
  walletBtn.title = "Copy to clipboard";
  walletBtn.textContent = `Wallet UUID: ${state.activeWalletUuid || "—"}`;
  walletBtn.disabled = !state.activeWalletUuid;
  walletBtn.addEventListener("click", async () => {
    if (!state.activeWalletUuid) return;
    await copyWithFeedback(walletBtn, state.activeWalletUuid);
  });

  const didBtn = document.createElement("button");
  didBtn.type = "button";
  didBtn.className = "btnPill mono";
  didBtn.title = "Copy to clipboard";
  didBtn.textContent = `DID: ${didText}`;
  didBtn.disabled = !didBase;
  didBtn.addEventListener("click", async () => {
    if (!didBase) return;
    await copyWithFeedback(didBtn, didBase);
  });

  row.append(walletNameBtn, walletBtn, didBtn);
  wrap.append(label, row);
  return wrap;
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
  el.vdrCreateEndpoint.value = DEFAULTS.vdrCreateEndpoint;
  el.httpSchemeOverride.value = DEFAULTS.httpSchemeOverridePairs;
  el.httpHeadersFor.value = DEFAULTS.httpHeadersPairs;
  el.didResolveInput.value = "";

  await init();

  setInlineStatus(el.httpOptionsStatus, "ok", "Applied (defaults)");

  state.didResolver = DIDResolver.new_thin(DEFAULTS.vdgHost, getHttpOptions());

  state.ready = true;
  setPill(el.appStatus, "ok", "Ready");

  await refreshWalletRecords({ autoSelectSingle: true });
  renderVmsEmpty("Select an active DID to load keys.");
  updateWalletDependentUi();
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
  if (state.didMutationInFlight) return;
  if (Date.now() < state.didMutationCooldownUntilMs) return;
  state.didMutationInFlight = true;
  updateWalletDependentUi();
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
    state.activeDidFq = didFq;
    await refreshControlledDids();
    await refreshLocallyControlledVerificationMethods();
    startDidMutationCooldown();
  } catch (e) {
    console.error(e);
    setInlineStatus(el.walletOpsStatus, "bad", String(e));
  } finally {
    state.didMutationInFlight = false;
    updateWalletDependentUi();
  }
}

async function handleUpdateDid() {
  if (!state.wallet || !state.activeDidFq) return;
  if (state.didMutationInFlight) return;
  if (Date.now() < state.didMutationCooldownUntilMs) return;
  state.didMutationInFlight = true;
  updateWalletDependentUi();
  setInlineStatus(el.walletOpsStatus, "warn", "Updating DID…");
  try {
    ensureHttpOptionsUpToDate();
    const didBase = getActiveDidBase();
    // Ensure local view is current before building the update.
    await fetchDidWithRetry({ didBase, attempts: 3, delayMs: 250 });
    const did = DID.try_from_string(didBase);
    const mbUpdateKey = mbHashFunctionDefault();
    const params = UpdateDIDParameters.new(did, null, mbUpdateKey);
    const didFq = await state.wallet.update_did(params, getHttpOptions());
    setInlineStatus(el.walletOpsStatus, "ok", "DID updated");
    state.activeDidFq = didFq;
    // Re-fetch right after updating to reduce the chance we attempt a later update
    // while the local doc chain is still settling.
    await fetchDidWithRetry({ didBase, attempts: 3, delayMs: 250 });
    await refreshControlledDids();
    await refreshLocallyControlledVerificationMethods();
    startDidMutationCooldown();
  } catch (e) {
    console.error(e);
    setInlineStatus(el.walletOpsStatus, "bad", String(e));
  } finally {
    state.didMutationInFlight = false;
    updateWalletDependentUi();
  }
}

async function handleDeactivateDidConfirmed() {
  if (!state.wallet || !state.activeDidFq) return;
  if (state.didMutationInFlight) return;
  if (Date.now() < state.didMutationCooldownUntilMs) return;
  state.didMutationInFlight = true;
  updateWalletDependentUi();
  setInlineStatus(el.walletOpsStatus, "warn", "Deactivating DID…");
  try {
    ensureHttpOptionsUpToDate();
    const didBase = getActiveDidBase();
    const did = DID.try_from_string(didBase);
    const params = DeactivateDIDParameters.new(did, null);
    const didFq = await state.wallet.deactivate_did(params, getHttpOptions());
    setInlineStatus(el.walletOpsStatus, "ok", "DID deactivated");
    state.activeDidFq = didFq;
    await refreshControlledDids();
    await refreshLocallyControlledVerificationMethods();
    startDidMutationCooldown();
  } catch (e) {
    console.error(e);
    setInlineStatus(el.walletOpsStatus, "bad", String(e));
  } finally {
    state.didMutationInFlight = false;
    updateWalletDependentUi();
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

async function withEphemeralSigner({ keyPurpose, purposeLabel }, fn) {
  if (!state.wallet) throw new Error("No active wallet selected");
  if (!state.activeDidFq) throw new Error("No active DID selected");

  ensureHttpOptionsUpToDate();
  const didBase = getActiveDidBase();
  const offline = Boolean(el.signingOffline.checked);

  if (!offline) {
    try {
      await state.wallet.fetch_did(didBase, getHttpOptions());
    } catch (e) {
      throw new Error(`Failed to fetch DID before ${purposeLabel}: ${String(e)}`);
    }
  }

  const signer = await state.wallet.new_wallet_based_signer(
    didBase,
    keyPurpose,
    null,
    getHttpOptions(),
  );
  return await fn(signer);
}

async function handleSignJwt() {
  if (!state.wallet || !state.activeDidFq) return;
  const defaultClaims = prettyJson({
    iss: getActiveDidBase() || "did:webplus:example",
    sub: "https://example.org/subject",
    aud: "https://example.org/audience",
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
    name: "Grunty McParty",
    email: "g@mc-p.org",
  });

  const purposeWrap = document.createElement("div");
  purposeWrap.className = "formRow";
  const label = document.createElement("label");
  label.className = "label";
  label.textContent = "Key purpose";
  const select = document.createElement("select");
  select.className = "select";
  select.id = "signJwtModalKeyPurpose";
  for (const v of [
    "assertionMethod",
    "authentication",
    "keyAgreement",
    "capabilityInvocation",
    "capabilityDelegation",
  ]) {
    const opt = document.createElement("option");
    opt.value = v;
    opt.textContent = v;
    select.appendChild(opt);
  }
  select.value = "assertionMethod";
  purposeWrap.append(label, select);

  const extra = document.createElement("div");
  extra.appendChild(buildSigningContextEl());
  extra.appendChild(purposeWrap);

  openJsonEditorV2({
    title: "Sign JWT",
    subtitle: "JWT claims (JSON)",
    defaultValue: defaultClaims,
    extraEl: extra,
  });

  const { ok, text } = await waitForJsonEditorOk();
  if (!ok) return;
  try {
    setInlineStatus(el.signingStatus, "warn", "Signing JWT…");
    const claims = safeJsonParse(text);
    const keyPurpose = String(select.value ?? "").trim() || "assertionMethod";
    const jwt = await withEphemeralSigner(
      { keyPurpose, purposeLabel: "JWT signing" },
      async (signer) => await jwt_sign(claims, signer),
    );
    setSignedArtifact(jwt);
    setInlineStatus(el.signingStatus, "ok", "JWT signed");
  } catch (e) {
    console.error(e);
    setInlineStatus(el.signingStatus, "bad", String(e));
  }
}

async function handleIssueVcJwtOrLdp({ format }) {
  if (!state.wallet || !state.activeDidFq) return;
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
  const fmt = format.toUpperCase();
  openJsonEditorV2({
    title: `Issue VC (${fmt})`,
    subtitle: `Unsigned VC input (${fmt})`,
    defaultValue,
    extraEl: buildSigningContextEl(),
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
    const keyPurpose = "assertionMethod";
    await withEphemeralSigner(
      { keyPurpose, purposeLabel: `VC issuance (${format.toUpperCase()})` },
      async (signer) => {
        if (format === "jwt") {
          const vcJwt = await issue_vc_jwt(unsignedVc, signer);
          setSignedArtifact(vcJwt);
        } else {
          const vcLdp = await issue_vc_ldp(unsignedVc, signer, state.didResolver);
          setSignedArtifact(stringifyForArtifact(vcLdp));
        }
      },
    );
    setInlineStatus(el.signingStatus, "ok", `VC issued (${format.toUpperCase()})`);
  } catch (e) {
    console.error(e);
    setInlineStatus(el.signingStatus, "bad", String(e));
  }
}

async function handleIssueVpJwtOrLdp({ format }) {
  if (!state.wallet || !state.activeDidFq) return;
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
  const fmt = format.toUpperCase();
  openJsonEditorV2({
    title: `Issue VP (${fmt})`,
    subtitle: `Unsigned VP input (${fmt})`,
    defaultValue: prettyJson(inputDefault),
    extraEl: buildSigningContextEl(),
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
    const keyPurpose = "authentication";
    await withEphemeralSigner(
      { keyPurpose, purposeLabel: `VP issuance (${format.toUpperCase()})` },
      async (signer) => {
        if (format === "jwt") {
          const vpJwt = await issue_vp_jwt(unsignedVp, issueParams, signer);
          setSignedArtifact(vpJwt);
        } else {
          const vpLdp = await issue_vp_ldp(unsignedVp, issueParams, signer, state.didResolver);
          setSignedArtifact(stringifyForArtifact(vpLdp));
        }
      },
    );
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

  el.refreshWalletsBtn.addEventListener("click", async () => {
    await refreshWalletRecords({ autoSelectSingle: true });
  });

  el.createWalletBtn.addEventListener("click", async () => {
    setInlineStatus(el.walletsStatus, "warn", "Creating…");
    try {
      const before = new Set(state.walletRecords.map((r) => r.wallet_uuid()));
      const name = (el.newWalletName.value ?? "").trim();
      const createdWallet = await Wallet.create(
        DEFAULTS.walletDbName,
        name ? name : null,
        DEFAULTS.vdgHost,
      );
      el.newWalletName.value = "";
      await refreshWalletRecords({ autoSelectSingle: false });
      const after = state.walletRecords.map((r) => r.wallet_uuid());
      const newlyCreatedUuid = after.find((uuid) => !before.has(uuid)) ?? "";
      const chosenUuid = newlyCreatedUuid || pickNewestWalletUuid(state.walletRecords);
      if (chosenUuid) {
        state.wallet = createdWallet;
        state.activeWalletUuid = chosenUuid;
        setActiveWalletSummary();
        await refreshWalletRecords({ autoSelectSingle: false });
        state.activeDidFq = "";
        setActiveDidSummary();
        await refreshControlledDids();
        await refreshLocallyControlledVerificationMethods();
        setSignedArtifact("");
        updateWalletDependentUi();
      }
      setInlineStatus(el.walletsStatus, "ok", "Created");
    } catch (e) {
      console.error(e);
      setInlineStatus(el.walletsStatus, "bad", String(e));
    }
  });

  el.refreshDidsBtn.addEventListener("click", async () => {
    if (!state.wallet) return;
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

  el.copyDidResolutionBtn.addEventListener("click", async () => {
    await copyTextToClipboard(el.didResolveOutput.value);
  });
  el.didResolveBtn.addEventListener("click", handleResolveDid);

  el.copySignedArtifactBtn.addEventListener("click", async () => {
    await copyTextToClipboard(el.signedArtifactOutput.value);
  });

  el.activeWalletHeaderNameBtn.addEventListener("click", async () => {
    const rec =
      state.walletRecords.find((r) => (r.wallet_uuid?.() ?? "") === state.activeWalletUuid) ??
      null;
    const name = rec ? getWalletRecordName(rec) : "";
    if (!name) return;
    await copyWithFeedback(el.activeWalletHeaderNameBtn, name);
  });

  el.activeWalletHeaderUuidBtn.addEventListener("click", async () => {
    if (!state.activeWalletUuid) return;
    await copyWithFeedback(el.activeWalletHeaderUuidBtn, state.activeWalletUuid);
  });

  el.activeDidHeaderDidBtn.addEventListener("click", async () => {
    const base = getActiveDidBase();
    if (!base) return;
    await copyWithFeedback(el.activeDidHeaderDidBtn, base);
  });

  el.activeDidSummarySelfHashBtn.addEventListener("click", async () => {
    const { selfHash } = parseDidFq(state.activeDidFq);
    if (!selfHash) return;
    await copyWithFeedback(el.activeDidSummarySelfHashBtn, selfHash);
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

