import { createHash } from "node:crypto";

export const PUBLIC_ENDPOINTS = Object.freeze({
  sui: "https://graphql.testnet.sui.io/graphql",
  walrus: "https://aggregator.walrus-testnet.walrus.space",
});
const PACKAGE = "0x5bbc666e64ca4b864a20207a8fab093619ff00685a0926abc872033e1549f8fb";
const ROOT_TYPE = `${PACKAGE}::owner_root::OwnerRoot`;
const EVENT_TYPE = `${PACKAGE}::owner_root::RootAdvanced`;
export const INPUT_LIMIT = 16 * 1024 * 1024;
const QUERIES = {
  transaction: `query transaction($digest: String!) { transaction(digest: $digest) { digest effects { status timestamp checkpoint { sequenceNumber } } } }`,
  changes: `query changes($digest: String!, $after: String) { transaction(digest: $digest) { effects { objectChanges(first: 50, after: $after) { pageInfo { hasNextPage endCursor } nodes { address outputState { version asMoveObject { contents { type { repr } json } } } } } } } }`,
  events: `query events($digest: String!, $after: String) { transaction(digest: $digest) { effects { events(first: 50, after: $after) { pageInfo { hasNextPage endCursor } nodes { contents { type { repr } json } } } } } }`,
  latest: `query latest($address: SuiAddress!) { object(address: $address) { version asMoveObject { contents { type { repr } json } } previousTransaction { digest } } }`,
};
const PATTERNS = {
  sha: /^sha256:[a-f0-9]{64}$/,
  object: /^0x[a-f0-9]{64}$/,
  owner: /^simiri-owner-v1:[a-f0-9]{64}$/,
  opaque: /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/,
  blob: /^[A-Za-z0-9_-]{43}$/,
  patch: /^[A-Za-z0-9_-]{50}$/,
  digest: /^[1-9A-HJ-NP-Za-km-z]{32,64}$/,
};
const KINDS = new Set([
  "transaction",
  "itemization",
  "evidence",
  "permission",
  "decision",
  "conflict",
  "checkpoint",
]);
class Failure extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}
function need(value, code = "INPUT_INVALID") {
  if (!value) throw new Failure(code);
}
function shape(value, required, optional = []) {
  need(value !== null && typeof value === "object" && !Array.isArray(value));
  need(Object.getPrototypeOf(value) === Object.prototype);
  need(required.every((key) => Object.hasOwn(value, key)));
  need(Object.keys(value).every((key) => required.includes(key) || optional.includes(key)));
}
function pattern(value, name) {
  need(typeof value === "string" && PATTERNS[name].test(value));
  if (name === "blob" || name === "patch") {
    const bytes = Buffer.from(value, "base64url");
    need(bytes.toString("base64url") === value && bytes.length === (name === "blob" ? 32 : 37));
    if (name === "patch") need(bytes[32] === 1 && bytes.readUInt16LE(33) < bytes.readUInt16LE(35));
  }
}
function integer(value, min = 1) {
  need(Number.isSafeInteger(value) && value >= min);
}
function list(value, max, validate, min = 0) {
  need(Array.isArray(value) && value.length >= min && value.length <= max);
  value.forEach(validate);
}
function locator(value) {
  need(typeof value === "string");
  pattern(value, value.length === 43 ? "blob" : "patch");
}
const quiltBlob = (patch) => Buffer.from(patch, "base64url").subarray(0, 32).toString("base64url");
function location(value, linked = false) {
  shape(value, ["blobId", "ciphertextCommitment", ...(linked ? ["checkpointCommitment"] : [])]);
  locator(value.blobId);
  pattern(value.ciphertextCommitment, "sha");
  if (linked) pattern(value.checkpointCommitment, "sha");
}
const hash = (bytes) => `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
const asAddress = (value) => `0x${value.slice(7)}`;
const ownerHash = (owner) => hash(`simiri.financial-memory.owner-ref.v1\0${owner}`);
const pathFor = (id) =>
  PATTERNS.patch.test(id) ? `/v1/blobs/by-quilt-patch-id/${id}` : `/v1/blobs/${id}`;

function validateInput(input) {
  shape(input, ["network", "ownerRef", "account", "root", "record"], ["witness"]);
  need(input.network === "testnet");
  pattern(input.ownerRef, "owner");
  shape(input.account, ["accountId", "accountOwnerAddress"]);
  for (const value of Object.values(input.account)) pattern(value, "object");
  const root = input.root;
  shape(root, ["objectId", "version", "commitment", "policyEpoch", "certification", "manifest"]);
  pattern(root.objectId, "object");
  integer(root.version);
  integer(root.policyEpoch);
  pattern(root.commitment, "sha");
  shape(root.certification, ["transactionDigest", "checkpoint", "checkpointCommitment"]);
  pattern(root.certification.transactionDigest, "digest");
  integer(root.certification.checkpoint);
  pattern(root.certification.checkpointCommitment, "sha");
  location(root.manifest);
  const record = input.record;
  shape(
    record,
    ["recordId", "ownerRef", "walrusBlobId", "ciphertextCommitment"],
    ["walrusQuiltPatchId"],
  );
  pattern(record.recordId, "opaque");
  pattern(record.ownerRef, "owner");
  need(record.ownerRef === input.ownerRef);
  pattern(record.walrusBlobId, "blob");
  pattern(record.ciphertextCommitment, "sha");
  if (record.walrusQuiltPatchId !== undefined) {
    pattern(record.walrusQuiltPatchId, "patch");
    need(quiltBlob(record.walrusQuiltPatchId) === record.walrusBlobId);
  }
  if (input.witness !== undefined) validateWitness(input.witness);
}

/** Only these two pinned public services are reachable. Timeout includes the response body. */
export function publicTransport({ fetch = globalThis.fetch, timeoutMs = 10_000, signal } = {}) {
  async function request(url, init, limit, json) {
    const timerController = new AbortController();
    const timer = setTimeout(() => timerController.abort(), timeoutMs);
    const combined = signal
      ? AbortSignal.any([signal, timerController.signal])
      : timerController.signal;
    let rejectAborted;
    const aborted = new Promise((_, reject) => {
      rejectAborted = () => reject(new Failure("PUBLIC_READ_TIMEOUT"));
    });
    combined.addEventListener("abort", rejectAborted, { once: true });
    if (combined.aborted) rejectAborted();
    let reader;
    let response;
    try {
      response = await Promise.race([
        fetch(url, {
          ...init,
          signal: combined,
          redirect: "error",
          credentials: "omit",
          cache: "no-store",
          referrerPolicy: "no-referrer",
        }),
        aborted,
      ]);
      need(response.ok && !response.redirected, "PUBLIC_HTTP_FAILED");
      const length = response.headers.get("content-length");
      if (length !== null)
        need(/^\d+$/.test(length) && Number(length) <= limit, "PUBLIC_RESPONSE_TOO_LARGE");
      need(response.body, "PUBLIC_RESPONSE_INVALID");
      reader = response.body.getReader();
      const chunks = [];
      let size = 0;
      for (;;) {
        const part = await Promise.race([reader.read(), aborted]);
        if (part.done) break;
        size += part.value.byteLength;
        need(size <= limit, "PUBLIC_RESPONSE_TOO_LARGE");
        chunks.push(part.value);
      }
      const bytes = Buffer.concat(chunks, size);
      if (!json) return bytes;
      const body = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
      need(
        body && !body.errors && body.data && typeof body.data === "object",
        "PUBLIC_GRAPHQL_FAILED",
      );
      return body.data;
    } catch (error) {
      throw error instanceof Failure ? error : new Failure("PUBLIC_READ_FAILED");
    } finally {
      clearTimeout(timer);
      combined.removeEventListener("abort", rejectAborted);
      timerController.abort();
      if (reader) void reader.cancel().catch(() => {});
      else if (response?.body) void response.body.cancel().catch(() => {});
    }
  }
  return {
    graphql(operation, variables) {
      need(Object.hasOwn(QUERIES, operation), "PUBLIC_QUERY_INVALID");
      return request(
        PUBLIC_ENDPOINTS.sui,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ query: QUERIES[operation], variables }),
        },
        2 * 1024 * 1024,
        true,
      );
    },
    walrus(id) {
      locator(id);
      return request(PUBLIC_ENDPOINTS.walrus + pathFor(id), { method: "GET" }, INPUT_LIMIT, false);
    },
  };
}

function decimalEqual(value, expected) {
  return (
    (typeof value === "string" &&
      /^(0|[1-9]\d*)$/.test(value) &&
      BigInt(value) === BigInt(expected)) ||
    (Number.isSafeInteger(value) && value === expected)
  );
}
function manifestId(value) {
  if (Array.isArray(value)) {
    need(
      value.length <= 128 && value.every((x) => Number.isInteger(x) && x >= 0 && x <= 255),
      "ROOT_MANIFEST_MISMATCH",
    );
    return new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.from(value));
  }
  need(
    typeof value === "string" && Buffer.from(value, "base64").toString("base64") === value,
    "ROOT_MANIFEST_MISMATCH",
  );
  return new TextDecoder("utf-8", { fatal: true }).decode(Buffer.from(value, "base64"));
}
function rootFields(fields, input) {
  const root = input.root;
  need(fields && decimalEqual(fields.root_version, root.version), "ROOT_VERSION_MISMATCH");
  need(fields.root_commitment === asAddress(root.commitment), "ROOT_COMMITMENT_MISMATCH");
  need(
    fields.checkpoint_commitment === asAddress(root.certification.checkpointCommitment),
    "ROOT_CHECKPOINT_MISMATCH",
  );
  need(
    fields.checkpoint_manifest_ciphertext_commitment ===
      asAddress(root.manifest.ciphertextCommitment),
    "ROOT_MANIFEST_MISMATCH",
  );
  need(
    manifestId(fields.checkpoint_manifest_blob_id) === root.manifest.blobId,
    "ROOT_MANIFEST_MISMATCH",
  );
}
function ownerFields(fields, input) {
  need(
    fields.owner_ref_commitment === asAddress(ownerHash(input.ownerRef)),
    "OWNER_BINDING_MISMATCH",
  );
  need(
    fields.memwal_account_id === input.account.accountId &&
      fields.account_owner_address === input.account.accountOwnerAddress,
    "ACCOUNT_BINDING_MISMATCH",
  );
  need(
    decimalEqual(fields.network, 0) &&
      decimalEqual(fields.schema_version, 1) &&
      decimalEqual(fields.policy_epoch, input.root.policyEpoch),
    "ROOT_POLICY_MISMATCH",
  );
}
async function pages(transport, operation, digest) {
  const nodes = [];
  const seen = new Set();
  let after = null;
  const field = operation === "changes" ? "objectChanges" : "events";
  for (let n = 0; n < 20; n++) {
    const data = await transport.graphql(operation, { digest, after });
    const page = data.transaction?.effects?.[field];
    need(
      page &&
        Array.isArray(page.nodes) &&
        page.nodes.length <= 50 &&
        typeof page.pageInfo?.hasNextPage === "boolean",
      "PUBLIC_PAGE_INVALID",
    );
    nodes.push(...page.nodes);
    if (!page.pageInfo.hasNextPage) return nodes;
    const cursor = page.pageInfo.endCursor;
    need(
      typeof cursor === "string" && cursor.length > 0 && cursor.length <= 1024 && !seen.has(cursor),
      "PUBLIC_PAGINATION_INVALID",
    );
    seen.add(cursor);
    after = cursor;
  }
  throw new Failure("PUBLIC_PAGE_LIMIT");
}
function memo(work) {
  let result;
  return () => (result ??= Promise.resolve().then(work));
}

export async function verifyRecord(input, { fetch, now = Date.now, maxAgeHours = 24 } = {}) {
  const checks = [];
  let writtenAt;
  const run = async (id, work) => {
    try {
      await work();
      checks.push({ id, status: "PASS", code: "OK" });
    } catch (error) {
      checks.push({
        id,
        status: "FAIL",
        code: error instanceof Failure ? error.code : "VERIFICATION_FAILED",
      });
    }
  };
  await run("input", () => {
    need(Number.isFinite(maxAgeHours) && maxAgeHours > 0 && maxAgeHours <= 8760);
    validateInput(input);
  });
  if (checks[0].status === "FAIL") return { ok: false, checks };
  const deadline = new AbortController();
  const timer = setTimeout(() => deadline.abort(), 60_000);
  try {
    const transport = publicTransport({ fetch, signal: deadline.signal });
    const { root } = input;
    const digest = root.certification.transactionDigest;
    const transaction = memo(async () => {
      const tx = (await transport.graphql("transaction", { digest })).transaction;
      need(
        tx && tx.digest === digest && tx.effects?.status === "SUCCESS",
        "CERTIFICATION_TRANSACTION_INVALID",
      );
      return tx;
    });
    const state = memo(async () => {
      await transaction();
      const states = (await pages(transport, "changes", digest)).filter(
        (x) => x.address === root.objectId,
      );
      need(states.length === 1, "ROOT_OBJECT_MISSING");
      const state = states[0].outputState;
      need(
        state?.asMoveObject?.contents?.type?.repr === ROOT_TYPE &&
          /^[1-9]\d*$/.test(String(state.version)),
        "ROOT_TYPE_INVALID",
      );
      return state;
    });
    await run("sui-root", async () =>
      rootFields((await state()).asMoveObject.contents.json, input),
    );
    await run("owner-binding", async () =>
      ownerFields((await state()).asMoveObject.contents.json, input),
    );
    await run("certification", async () => {
      const tx = await transaction();
      need(
        decimalEqual(tx.effects.checkpoint?.sequenceNumber, root.certification.checkpoint),
        "CERTIFICATION_CHECKPOINT_MISMATCH",
      );
      const events = (await pages(transport, "events", digest)).filter(
        (x) =>
          x.contents?.type?.repr === EVENT_TYPE &&
          x.contents.json?.root_id === root.objectId &&
          decimalEqual(x.contents.json.root_version, root.version),
      );
      need(events.length === 1, "CERTIFICATION_EVENT_MISSING");
      const event = events[0].contents.json;
      need(
        event.root_commitment === asAddress(root.commitment) &&
          event.checkpoint_commitment === asAddress(root.certification.checkpointCommitment) &&
          event.checkpoint_manifest_ciphertext_commitment ===
            asAddress(root.manifest.ciphertextCommitment),
        "CERTIFICATION_COMMITMENT_MISMATCH",
      );
      need(
        event.memwal_account_id === input.account.accountId &&
          event.account_owner_address === input.account.accountOwnerAddress &&
          decimalEqual(event.policy_epoch, root.policyEpoch) &&
          decimalEqual(event.network, 0) &&
          decimalEqual(event.schema_version, 1) &&
          decimalEqual(event.previous_root_version, root.version - 1),
        "CERTIFICATION_BINDING_MISMATCH",
      );
    });
    await run("manifest-hash", async () =>
      need(
        hash(await transport.walrus(root.manifest.blobId)) === root.manifest.ciphertextCommitment,
        "MANIFEST_HASH_MISMATCH",
      ),
    );
    await run("record-hash", async () =>
      need(
        hash(
          await transport.walrus(input.record.walrusQuiltPatchId ?? input.record.walrusBlobId),
        ) === input.record.ciphertextCommitment,
        "RECORD_HASH_MISMATCH",
      ),
    );
    await run("record-inclusion", () => verifyWitness(input));
    await run("freshness", async () => {
      const tx = await transaction();
      writtenAt = tx.effects.timestamp;
      need(
        typeof writtenAt === "string" && /^\d{4}-\d\d-\d\dT/.test(writtenAt),
        "CERTIFICATION_TIME_INVALID",
      );
      const age = now() - Date.parse(writtenAt);
      need(
        Number.isFinite(age) && age >= -300_000 && age <= maxAgeHours * 3_600_000,
        "CERTIFICATION_NOT_FRESH",
      );
      const latest = (await transport.graphql("latest", { address: root.objectId })).object;
      need(latest?.asMoveObject?.contents?.type?.repr === ROOT_TYPE, "LATEST_ROOT_UNREADABLE");
      rootFields(latest.asMoveObject.contents.json, input);
      ownerFields(latest.asMoveObject.contents.json, input);
      need(
        String(latest.version) === String((await state()).version) &&
          latest.previousTransaction?.digest === digest,
        "ROOT_SUPERSEDED",
      );
      need(!input.witness?.checkpoints.some((x) => x.rebind?.kind === "RETIRED"), "ROOT_RETIRED");
    });
    return {
      ok: checks.every((check) => check.status === "PASS"),
      checks,
      rootVersion: root.version,
      ...(checks.at(-1).status === "PASS" ? { writtenAt } : {}),
    };
  } finally {
    clearTimeout(timer);
  }
}

function certification(value) {
  shape(
    value,
    [
      "network",
      "rootObjectId",
      "transactionDigest",
      "rootCommitment",
      "checkpointCommitment",
      "epoch",
    ],
    ["blobId"],
  );
  need(value.network === "testnet");
  pattern(value.rootObjectId, "object");
  pattern(value.transactionDigest, "digest");
  pattern(value.rootCommitment, "sha");
  pattern(value.checkpointCommitment, "sha");
  integer(value.epoch);
  if (value.blobId !== undefined) pattern(value.blobId, "blob");
}
function certifiedPointer(value) {
  shape(value, [
    "rootObjectId",
    "rootVersion",
    "rootCommitment",
    "checkpointCommitment",
    "manifest",
    "certification",
    "policyEpoch",
  ]);
  pattern(value.rootObjectId, "object");
  integer(value.rootVersion);
  integer(value.policyEpoch);
  pattern(value.rootCommitment, "sha");
  pattern(value.checkpointCommitment, "sha");
  location(value.manifest);
  certification(value.certification);
  need(
    value.certification.rootObjectId === value.rootObjectId &&
      value.certification.rootCommitment === value.rootCommitment &&
      value.certification.checkpointCommitment === value.checkpointCommitment,
  );
}
function marker(value, rebind) {
  const identity = ["version", "network", "ownerRefCommitment"];
  if (rebind) {
    need(value?.kind === "SUCCESSOR" || value?.kind === "RETIRED");
    shape(value, [
      ...identity,
      "kind",
      "rebindId",
      "accountId",
      "accountOwnerAddress",
      "predecessor",
      value.kind === "SUCCESSOR" ? "successorRootObjectId" : "successor",
    ]);
    pattern(value.rebindId, "opaque");
    pattern(value.accountId, "object");
    pattern(value.accountOwnerAddress, "object");
    certifiedPointer(value.predecessor);
    if (value.kind === "SUCCESSOR") pattern(value.successorRootObjectId, "object");
    else certifiedPointer(value.successor);
  } else {
    shape(value, [
      ...identity,
      "transitionId",
      "sourceRoot",
      "sourceAccount",
      "targetAccount",
      "sourceIndexGeneration",
      "targetIndexGeneration",
      "copies",
    ]);
    need(typeof value.transitionId === "string" && /^[a-f0-9]{64}$/.test(value.transitionId));
    certifiedPointer(value.sourceRoot);
    for (const account of [value.sourceAccount, value.targetAccount]) {
      shape(account, ["accountId", "accountOwnerAddress"]);
      for (const value of Object.values(account)) pattern(value, "object");
    }
    pattern(value.sourceIndexGeneration, "sha");
    pattern(value.targetIndexGeneration, "sha");
    list(value.copies, 1000, (copy) => {
      shape(copy, ["factId", "contentCommitment", "sourceBlobId", "targetBlobId"]);
      pattern(copy.factId, "opaque");
      pattern(copy.contentCommitment, "sha");
      pattern(copy.sourceBlobId, "blob");
      pattern(copy.targetBlobId, "blob");
    });
  }
  need(value.version === 1 && value.network === "testnet");
  pattern(value.ownerRefCommitment, "sha");
}
function reference(value, format) {
  const required = [
    "recordId",
    "recordKind",
    "ownerRef",
    "subjectRef",
    "fieldPaths",
    "walrusBlobId",
    "ciphertextCommitment",
    "envelopeCommitment",
    "encryptionPolicyId",
    "keyEpoch",
    "policyEpoch",
    "previousOwnerHeadCommitment",
  ];
  shape(
    value,
    [...required, ...(format === 1 ? ["certification"] : [])],
    ["walrusCertificationRef", "walrusQuiltPatchId", "walrusQuiltIdentifier"],
  );
  for (const key of ["recordId", "subjectRef", "encryptionPolicyId"]) pattern(value[key], "opaque");
  need(KINDS.has(value.recordKind));
  pattern(value.ownerRef, "owner");
  pattern(value.walrusBlobId, "blob");
  for (const key of ["ciphertextCommitment", "envelopeCommitment"]) pattern(value[key], "sha");
  integer(value.keyEpoch);
  integer(value.policyEpoch);
  list(value.fieldPaths, 100, (x) => pattern(x, "opaque"), 1);
  if (value.previousOwnerHeadCommitment !== null) pattern(value.previousOwnerHeadCommitment, "sha");
  if (value.walrusCertificationRef !== undefined)
    need(
      typeof value.walrusCertificationRef === "string" &&
        /^walrus:testnet:[A-Za-z0-9][A-Za-z0-9._:/-]{0,511}$/.test(value.walrusCertificationRef),
    );
  need((value.walrusQuiltPatchId === undefined) === (value.walrusQuiltIdentifier === undefined));
  if (value.walrusQuiltPatchId !== undefined) {
    pattern(value.walrusQuiltPatchId, "patch");
    need(quiltBlob(value.walrusQuiltPatchId) === value.walrusBlobId);
    need(
      typeof value.walrusQuiltIdentifier === "string" &&
        /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(value.walrusQuiltIdentifier),
    );
  }
  if (format === 1) {
    certification(value.certification);
    need(value.certification.blobId === value.walrusBlobId);
  }
}
function validateWitness(witness) {
  shape(witness, ["format", "restorePolicy", "checkpoints"]);
  need(witness.format === 1 || witness.format === 2);
  shape(witness.restorePolicy, ["allowedRecordKinds", "allowedFields"]);
  list(witness.restorePolicy.allowedRecordKinds, 7, (x) => need(KINDS.has(x)), 1);
  list(witness.restorePolicy.allowedFields, 100, (x) => x === "*" || pattern(x, "opaque"), 1);
  let count = 0;
  list(
    witness.checkpoints,
    witness.format === 1 ? 1 : 17,
    (checkpoint) => {
      const common = [
        "checkpointId",
        "ownerHeadCommitment",
        "recordCount",
        "records",
        "checkpointCommitment",
      ];
      shape(
        checkpoint,
        [
          ...common,
          ...(witness.format === 1
            ? ["recordIds", "manifestCommitment", "projectionVersion"]
            : ["format", "full", "previous", "chainLocations"]),
        ],
        witness.format === 2 ? ["rebind", "accountTransition"] : [],
      );
      pattern(checkpoint.checkpointId, "opaque");
      pattern(checkpoint.ownerHeadCommitment, "sha");
      pattern(checkpoint.checkpointCommitment, "sha");
      integer(checkpoint.recordCount, 0);
      list(checkpoint.records, 10_000, (x) => reference(x, witness.format));
      count += checkpoint.records.length;
      need(count <= 10_000);
      if (witness.format === 1) {
        list(checkpoint.recordIds, 10_000, (x) => pattern(x, "opaque"));
        pattern(checkpoint.manifestCommitment, "sha");
        integer(checkpoint.projectionVersion);
      } else {
        need(checkpoint.format === 2 && typeof checkpoint.full === "boolean");
        if (checkpoint.previous !== null) location(checkpoint.previous, true);
        list(checkpoint.chainLocations, 16, (x) => location(x, true));
        if (checkpoint.rebind !== undefined) marker(checkpoint.rebind, true);
        if (checkpoint.accountTransition !== undefined) marker(checkpoint.accountTransition, false);
      }
    },
    1,
  );
}
/** The existing protocol hashes sorted JSON keys, preserving array order. */
export function canonical(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean")
    return JSON.stringify(value);
  if (typeof value === "number") {
    need(Number.isFinite(value));
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  need(value && typeof value === "object");
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`)
    .join(",")}}`;
}
const commitment = (domain, value) => hash(`${domain}\0${canonical(value)}`);
function normalizedV1(record) {
  const c = record.certification;
  return {
    ...record,
    certification: {
      blobId: c.blobId,
      epoch: c.epoch,
      network: c.network,
      rootObjectId: c.rootObjectId,
      transactionDigest: c.transactionDigest,
    },
  };
}
export function checkpointCommitment(checkpoint, format) {
  if (format === 1) {
    const { checkpointCommitment: _ignored, ...rest } = checkpoint;
    return commitment("simiri.financial-memory.checkpoint.v1", {
      ...rest,
      records: rest.records.map(normalizedV1),
    });
  }
  return commitment("simiri.financial-memory.checkpoint.v2", {
    ...(checkpoint.rebind ? { rebind: checkpoint.rebind } : {}),
    ...(checkpoint.accountTransition ? { accountTransition: checkpoint.accountTransition } : {}),
    checkpointId: checkpoint.checkpointId,
    chainLocations: checkpoint.chainLocations,
    full: checkpoint.full,
    ownerHeadCommitment: checkpoint.ownerHeadCommitment,
    previous: checkpoint.previous,
    recordCount: checkpoint.recordCount,
    recordsCommitment: commitment("simiri.financial-memory.manifest.v2", checkpoint.records),
  });
}
function verifyWitness(input) {
  need(input.witness, "RECORD_INCLUSION_UNPROVEN");
  const { witness, root } = input;
  const mismatch = "RECORD_INCLUSION_MISMATCH";
  const all = [];
  const ids = new Set();
  let previous;
  for (const [index, checkpoint] of witness.checkpoints.entries()) {
    need(
      checkpointCommitment(checkpoint, witness.format) === checkpoint.checkpointCommitment,
      mismatch,
    );
    if (witness.format === 1) {
      need(
        checkpoint.manifestCommitment ===
          commitment("simiri.financial-memory.manifest.v1", checkpoint.records.map(normalizedV1)) &&
          checkpoint.projectionVersion === root.version &&
          canonical(checkpoint.recordIds) === canonical(checkpoint.records.map((x) => x.recordId)),
        mismatch,
      );
    } else {
      need(index === 0 ? checkpoint.full : !checkpoint.full, mismatch);
      need(checkpoint.chainLocations.length === index, mismatch);
      for (let n = 0; n < index; n++) {
        const nextLink = witness.checkpoints[n + 1].previous;
        need(
          nextLink &&
            nextLink.checkpointCommitment === witness.checkpoints[n].checkpointCommitment &&
            canonical(checkpoint.chainLocations[n]) === canonical(nextLink),
          mismatch,
        );
      }
      if (previous)
        need(checkpoint.previous?.checkpointCommitment === previous.checkpointCommitment, mismatch);
      for (const m of [checkpoint.rebind, checkpoint.accountTransition])
        if (m) need(m.ownerRefCommitment === ownerHash(input.ownerRef), mismatch);
      if (checkpoint.rebind?.kind === "SUCCESSOR")
        need(
          checkpoint.rebind.successorRootObjectId === root.objectId &&
            checkpoint.rebind.accountId === input.account.accountId &&
            checkpoint.rebind.accountOwnerAddress === input.account.accountOwnerAddress,
          mismatch,
        );
      if (checkpoint.accountTransition)
        need(
          canonical(checkpoint.accountTransition.targetAccount) === canonical(input.account),
          mismatch,
        );
    }
    let head = previous?.ownerHeadCommitment;
    for (const [indexInSegment, record] of checkpoint.records.entries()) {
      need(
        !ids.has(record.recordId) &&
          record.ownerRef === input.ownerRef &&
          record.policyEpoch <= root.policyEpoch,
        mismatch,
      );
      ids.add(record.recordId);
      if (indexInSegment > 0 || (witness.format === 2 && !checkpoint.full))
        need(record.previousOwnerHeadCommitment === head, mismatch);
      head = record.envelopeCommitment;
      need(
        witness.restorePolicy.allowedRecordKinds.includes(record.recordKind) &&
          record.fieldPaths.every((field) =>
            witness.restorePolicy.allowedFields.some(
              (allowed) => allowed === "*" || field === allowed || field.startsWith(`${allowed}.`),
            ),
          ),
        mismatch,
      );
      if (witness.format === 1)
        need(
          record.certification.rootObjectId === root.objectId &&
            record.certification.rootCommitment === root.commitment &&
            record.certification.checkpointCommitment === root.certification.checkpointCommitment,
          mismatch,
        );
      all.push(record);
    }
    need(
      checkpoint.recordCount === all.length &&
        (head === undefined || checkpoint.ownerHeadCommitment === head),
      mismatch,
    );
    previous = checkpoint;
  }
  const checkpoint = witness.checkpoints.at(-1);
  need(checkpoint.checkpointCommitment === root.certification.checkpointCommitment, mismatch);
  need(
    commitment("simiri.financial-memory.owner-root.v1", {
      checkpointCommitment: checkpoint.checkpointCommitment,
      checkpointId: checkpoint.checkpointId,
      ownerHeadCommitment: checkpoint.ownerHeadCommitment,
      ownerRef: input.ownerRef,
      policyEpoch: root.policyEpoch,
      restorePolicy: witness.restorePolicy,
      rootVersion: root.version,
    }) === root.commitment,
    mismatch,
  );
  const matches = all.filter((x) => x.recordId === input.record.recordId);
  need(matches.length === 1, "RECORD_REFERENCE_MISSING");
  const ref = matches[0];
  for (const key of ["ownerRef", "walrusBlobId", "ciphertextCommitment", "walrusQuiltPatchId"])
    need(ref[key] === input.record[key], mismatch);
}

export function formatReport(result) {
  return `${result.ok ? "PASS" : "FAIL"}\n${result.checks.map((row) => `${row.status} ${row.id} ${row.code}`).join("\n")}\n${result.writtenAt ? `Root version ${result.rootVersion}, transaction time ${result.writtenAt}\n` : ""}`;
}
