import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { formatReport, PUBLIC_ENDPOINTS, publicTransport, verifyRecord } from "./verifier-core.mjs";
import { main } from "./verify.mjs";

// Synthetic public metadata and ciphertext, never product or live acceptance evidence.
const object = (digit) => `0x${digit.repeat(64)}`;
const hash = (bytes) => `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
const address = (commitment) => `0x${commitment.slice(7)}`;
const ownerRef = `simiri-owner-v1:${"a".repeat(64)}`;
const now = Date.parse("2026-11-04T03:00:00.000Z");
const timestamp = "2026-11-04T02:00:00.000Z";
const rootType =
  "0x5bbc666e64ca4b864a20207a8fab093619ff00685a0926abc872033e1549f8fb::owner_root::OwnerRoot";
const eventType = rootType.replace("OwnerRoot", "RootAdvanced");
const digest = "3".repeat(44);
const blobId = (byte) => Buffer.alloc(32, byte).toString("base64url");
const patchId = (blob, version = 1, start = 1, end = 2) => {
  const suffix = Buffer.alloc(5);
  suffix[0] = version;
  suffix.writeUInt16LE(start, 1);
  suffix.writeUInt16LE(end, 3);
  return Buffer.concat([Buffer.from(blob, "base64url"), suffix]).toString("base64url");
};

function fixture({ patch = false } = {}) {
  const ciphertext = Buffer.from([0, 23, 45, 67, 89, 255]);
  const manifest = Buffer.from([1, 3, 5, 7, 9, 11]);
  const blob = blobId(2);
  const input = {
    network: "testnet",
    ownerRef,
    account: { accountId: object("3"), accountOwnerAddress: object("4") },
    root: {
      objectId: object("1"),
      version: 110,
      commitment: hash("root"),
      policyEpoch: 1,
      certification: {
        transactionDigest: digest,
        checkpoint: 1234,
        checkpointCommitment: hash("checkpoint"),
      },
      manifest: { blobId: patchId(blobId(3)), ciphertextCommitment: hash(manifest) },
    },
    record: {
      recordId: "record-1",
      ownerRef,
      walrusBlobId: blob,
      ciphertextCommitment: hash(ciphertext),
      ...(patch ? { walrusQuiltPatchId: patchId(blob) } : {}),
    },
  };
  const fields = {
    owner_ref_commitment: address(hash(`simiri.financial-memory.owner-ref.v1\0${ownerRef}`)),
    memwal_account_id: input.account.accountId,
    account_owner_address: input.account.accountOwnerAddress,
    root_version: "110",
    root_commitment: address(input.root.commitment),
    checkpoint_commitment: address(input.root.certification.checkpointCommitment),
    checkpoint_manifest_ciphertext_commitment: address(input.root.manifest.ciphertextCommitment),
    checkpoint_manifest_blob_id: Buffer.from(input.root.manifest.blobId).toString("base64"),
    policy_epoch: "1",
    network: 0,
    schema_version: 1,
  };
  const connection = (nodes) => ({ nodes, pageInfo: { hasNextPage: false, endCursor: null } });
  const event = {
    root_id: input.root.objectId,
    memwal_account_id: input.account.accountId,
    account_owner_address: input.account.accountOwnerAddress,
    previous_root_version: "109",
    root_version: "110",
    root_commitment: fields.root_commitment,
    checkpoint_commitment: fields.checkpoint_commitment,
    checkpoint_manifest_ciphertext_commitment: fields.checkpoint_manifest_ciphertext_commitment,
    policy_epoch: "1",
    network: 0,
    schema_version: 1,
  };
  const responses = {
    transaction: {
      transaction: {
        digest,
        effects: { status: "SUCCESS", timestamp, checkpoint: { sequenceNumber: "1234" } },
      },
    },
    changes: {
      transaction: {
        effects: {
          objectChanges: connection([
            {
              address: input.root.objectId,
              outputState: {
                version: "123456789012345678",
                asMoveObject: { contents: { type: { repr: rootType }, json: fields } },
              },
            },
          ]),
        },
      },
    },
    events: {
      transaction: {
        effects: { events: connection([{ contents: { type: { repr: eventType }, json: event } }]) },
      },
    },
    latest: {
      object: {
        version: "123456789012345678",
        asMoveObject: { contents: { type: { repr: rootType }, json: structuredClone(fields) } },
        previousTransaction: { digest },
      },
    },
  };
  const requests = [];
  const fetch = async (url, init) => {
    requests.push({ url, init });
    if (url === PUBLIC_ENDPOINTS.sui) {
      const body = JSON.parse(init.body);
      const operation = /query (\w+)/.exec(body.query)?.[1];
      assert.ok(Object.hasOwn(responses, operation), `unexpected operation ${operation}`);
      assert.equal(init.method, "POST");
      assert.equal(init.redirect, "error");
      assert.equal(init.credentials, "omit");
      return Response.json({ data: responses[operation] });
    }
    assert.equal(init.method, "GET");
    assert.equal(init.redirect, "error");
    assert.equal(init.credentials, "omit");
    const isManifest =
      url === PUBLIC_ENDPOINTS.walrus + "/v1/blobs/by-quilt-patch-id/" + input.root.manifest.blobId;
    const recordPath = patch
      ? `/v1/blobs/by-quilt-patch-id/${input.record.walrusQuiltPatchId}`
      : `/v1/blobs/${blob}`;
    assert.ok(
      isManifest || url === PUBLIC_ENDPOINTS.walrus + recordPath,
      "no other endpoint permitted",
    );
    return new Response(isManifest ? manifest : ciphertext);
  };
  return { input, responses, requests, fetch, fields, event, ciphertext, manifest };
}
const run = (f, options = {}) =>
  verifyRecord(f.input, { fetch: f.fetch, now: () => now, ...options });
const check = (result, id) => result.checks.find((row) => row.id === id);

// Independent specification builder, not imported from the verifier under test.
const canonical = (x) =>
  x === null || typeof x !== "object"
    ? JSON.stringify(x)
    : Array.isArray(x)
      ? `[${x.map(canonical).join(",")}]`
      : `{${Object.keys(x)
          .sort()
          .map((k) => JSON.stringify(k) + ":" + canonical(x[k]))
          .join(",")}}`;
const commit = (domain, value) => hash(domain + "\0" + canonical(value));
function witnessFixture(format = 2, { delta = false, patch = false, marker = null } = {}) {
  const f = fixture({ patch });
  const reference = {
    ...f.input.record,
    recordKind: "checkpoint",
    subjectRef: "subject-1",
    fieldPaths: ["owner-context.index"],
    envelopeCommitment: hash("envelope-1"),
    encryptionPolicyId: "policy-1",
    keyEpoch: 1,
    policyEpoch: 1,
    previousOwnerHeadCommitment: null,
    ...(patch ? { walrusQuiltIdentifier: "record-1" } : {}),
  };
  const restorePolicy = { allowedRecordKinds: ["checkpoint"], allowedFields: ["*"] };
  const pointer = {
    rootObjectId: object("8"),
    rootVersion: 1,
    rootCommitment: hash("previous root"),
    checkpointCommitment: hash("previous checkpoint"),
    manifest: { blobId: blobId(8), ciphertextCommitment: hash("previous manifest") },
    policyEpoch: 1,
    certification: {
      network: "testnet",
      rootObjectId: object("8"),
      transactionDigest: digest,
      rootCommitment: hash("previous root"),
      checkpointCommitment: hash("previous checkpoint"),
      epoch: 1233,
    },
  };
  const markerFields =
    marker === "account"
      ? {
          accountTransition: {
            version: 1,
            network: "testnet",
            transitionId: "b".repeat(64),
            ownerRefCommitment: hash(`simiri.financial-memory.owner-ref.v1\0${ownerRef}`),
            sourceRoot: pointer,
            sourceAccount: { accountId: object("8"), accountOwnerAddress: object("9") },
            targetAccount: f.input.account,
            sourceIndexGeneration: hash("old index"),
            targetIndexGeneration: hash("new index"),
            copies: [],
          },
        }
      : marker
        ? {
            rebind: {
              version: 1,
              network: "testnet",
              rebindId: "rebind-1",
              ownerRefCommitment: hash(`simiri.financial-memory.owner-ref.v1\0${ownerRef}`),
              accountId: f.input.account.accountId,
              accountOwnerAddress: f.input.account.accountOwnerAddress,
              predecessor: pointer,
              kind: marker === "retired" ? "RETIRED" : "SUCCESSOR",
              ...(marker === "retired"
                ? { successor: pointer }
                : { successorRootObjectId: f.input.root.objectId }),
            },
          }
        : {};
  let checkpoints;
  const sealV2 = (m) => ({
    ...m,
    checkpointCommitment: commit("simiri.financial-memory.checkpoint.v2", {
      ...(m.rebind ? { rebind: m.rebind } : {}),
      ...(m.accountTransition ? { accountTransition: m.accountTransition } : {}),
      checkpointId: m.checkpointId,
      chainLocations: m.chainLocations,
      full: m.full,
      ownerHeadCommitment: m.ownerHeadCommitment,
      previous: m.previous,
      recordCount: m.recordCount,
      recordsCommitment: commit("simiri.financial-memory.manifest.v2", m.records),
    }),
  });
  if (format === 2) {
    const base = sealV2({
      ...markerFields,
      format: 2,
      checkpointId: "checkpoint-1",
      full: true,
      previous: null,
      chainLocations: [],
      ownerHeadCommitment: reference.envelopeCommitment,
      recordCount: 1,
      records: [reference],
    });
    checkpoints = [base];
    if (delta) {
      const previous = {
        blobId: blobId(4),
        ciphertextCommitment: hash("older encrypted manifest"),
        checkpointCommitment: base.checkpointCommitment,
      };
      const second = {
        ...reference,
        recordId: "record-2",
        previousOwnerHeadCommitment: reference.envelopeCommitment,
        envelopeCommitment: hash("envelope-2"),
      };
      checkpoints.push(
        sealV2({
          format: 2,
          checkpointId: "checkpoint-2",
          full: false,
          previous,
          chainLocations: [previous],
          ownerHeadCommitment: second.envelopeCommitment,
          recordCount: 2,
          records: [second],
        }),
      );
    }
  } else {
    const fullReference = {
      ...reference,
      certification: {
        network: "testnet",
        rootObjectId: f.input.root.objectId,
        transactionDigest: digest,
        epoch: 1234,
        blobId: reference.walrusBlobId,
      },
    };
    const base = {
      checkpointId: "checkpoint-1",
      ownerHeadCommitment: reference.envelopeCommitment,
      recordIds: [reference.recordId],
      manifestCommitment: commit("simiri.financial-memory.manifest.v1", [fullReference]),
      projectionVersion: 110,
      recordCount: 1,
      records: [fullReference],
    };
    checkpoints = [
      { ...base, checkpointCommitment: commit("simiri.financial-memory.checkpoint.v1", base) },
    ];
  }
  const head = checkpoints.at(-1);
  f.input.root.certification.checkpointCommitment = head.checkpointCommitment;
  f.input.root.commitment = commit("simiri.financial-memory.owner-root.v1", {
    checkpointCommitment: head.checkpointCommitment,
    checkpointId: head.checkpointId,
    ownerHeadCommitment: head.ownerHeadCommitment,
    ownerRef,
    policyEpoch: 1,
    restorePolicy,
    rootVersion: 110,
  });
  if (format === 1) {
    // These two certification fields are deliberately excluded by the V1 algorithm.
    const cert = head.records[0].certification;
    cert.rootCommitment = f.input.root.commitment;
    cert.checkpointCommitment = head.checkpointCommitment;
  }
  f.input.witness = { format, restorePolicy, checkpoints };
  f.fields.root_commitment = address(f.input.root.commitment);
  f.fields.checkpoint_commitment = address(head.checkpointCommitment);
  f.event.root_commitment = f.fields.root_commitment;
  f.event.checkpoint_commitment = f.fields.checkpoint_commitment;
  f.responses.latest.object.asMoveObject.contents.json = structuredClone(f.fields);
  return f;
}

for (const format of [1, 2])
  test(`complete owner-opt-in V${format} witness proves membership and passes overall`, async () => {
    const result = await run(witnessFixture(format));
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.ok(result.checks.every((row) => row.status === "PASS"));
    assert.match(formatReport(result), /^PASS\n/);
  });

test("V2 full plus delta chain and quilt record prove inclusion", async () => {
  const result = await run(witnessFixture(2, { delta: true, patch: true }));
  assert.equal(result.ok, true, JSON.stringify(result));
});

for (const marker of ["account", "successor"])
  test(`committed ${marker} metadata is accepted without claiming execution correctness`, async () => {
    const result = await run(witnessFixture(2, { marker }));
    assert.equal(result.ok, true, JSON.stringify(result));
  });

test("a certified retirement marker fails freshness rather than silently following a successor", async () => {
  const result = await run(witnessFixture(2, { marker: "retired" }));
  assert.equal(check(result, "record-inclusion").status, "PASS");
  assert.equal(check(result, "freshness").code, "ROOT_RETIRED");
  assert.equal(result.ok, false);
});

test("private fields in transition/rebind metadata are rejected before any public request", async () => {
  for (const marker of ["account", "successor"]) {
    const f = witnessFixture(2, { marker });
    const checkpoint = f.input.witness.checkpoints[0];
    (checkpoint.rebind ?? checkpoint.accountTransition).privateText = "PRIVATE_SENTINEL";
    const result = await run(f);
    assert.equal(check(result, "input").status, "FAIL");
    assert.equal(f.requests.length, 0);
  }
});

for (const [format, patch, expected] of [
  [1, false, "sha256:d5a8d40e0f7f2878272ff0a88916442e5a7616b8e21ce71e1a55639e9d71c5bc"],
  [2, false, "sha256:abf23abcf9f09b3668c2d7ca40d98d03981a48a40739383ba57398d70a733965"],
  [2, true, "sha256:9d2b4471ce745f1ee5cfbdc1d57fed8493190c95e8d589559a61d6725fa107f4"],
])
  test(`V${format} patch=${patch} vector matches production8adca4e2a commitment`, async () => {
    const f = witnessFixture(format, { patch });
    assert.equal(f.input.root.certification.checkpointCommitment, expected);
    assert.equal((await run(f)).ok, true);
  });

for (const [name, mutate] of [
  [
    "record removed",
    (f) => {
      f.input.witness.checkpoints[0].records = [];
    },
  ],
  [
    "selected ref absent",
    (f) => {
      f.input.record.recordId = "record-not-present";
    },
  ],
  [
    "record bytes swapped",
    (f) => {
      f.input.record.ciphertextCommitment = hash("unrelated");
    },
  ],
  [
    "record locator swapped",
    (f) => {
      f.input.record.walrusBlobId = blobId(5);
    },
  ],
  [
    "record owner swapped",
    (f) => {
      f.input.witness.checkpoints[0].records[0].ownerRef = `simiri-owner-v1:${"b".repeat(64)}`;
    },
  ],
  [
    "record count forged",
    (f) => {
      f.input.witness.checkpoints[0].recordCount = 2;
    },
  ],
  [
    "root preimage policy forged",
    (f) => {
      f.input.witness.restorePolicy.allowedFields = ["some.other.field"];
    },
  ],
  [
    "checkpoint hash forged",
    (f) => {
      f.input.witness.checkpoints[0].checkpointCommitment = hash("forged");
    },
  ],
  [
    "root commitment forged",
    (f) => {
      f.input.root.commitment = hash("forged");
    },
  ],
  [
    "owner-head chain forged",
    (f) => {
      f.input.witness.checkpoints[0].ownerHeadCommitment = hash("forged");
    },
  ],
  [
    "duplicate references",
    (f) => {
      f.input.witness.checkpoints[0].records.push(
        structuredClone(f.input.witness.checkpoints[0].records[0]),
      );
    },
  ],
])
  test(`witness FAIL: ${name}`, async () => {
    const f = witnessFixture();
    mutate(f);
    const result = await run(f);
    assert.equal(result.ok, false);
    assert.equal(check(result, "record-inclusion")?.status, "FAIL", JSON.stringify(result));
  });

test("V2 missing, reordered or broken delta chain cannot pass", async () => {
  for (const mutate of [
    (f) => {
      f.input.witness.checkpoints.shift();
    },
    (f) => {
      f.input.witness.checkpoints.reverse();
    },
    (f) => {
      f.input.witness.checkpoints[1].previous.checkpointCommitment = hash("wrong predecessor");
    },
    (f) => {
      f.input.witness.checkpoints[1].chainLocations = [];
    },
    (f) => {
      f.input.witness.checkpoints[1].records[0].previousOwnerHeadCommitment =
        hash("wrong owner chain");
    },
  ]) {
    const f = witnessFixture(2, { delta: true });
    mutate(f);
    assert.equal(check(await run(f), "record-inclusion")?.status, "FAIL");
  }
});

test("witness never accepts fact text or decryption material", async () => {
  for (const field of ["factText", "plaintext", "key", "ownerFacts"]) {
    const f = witnessFixture();
    f.input.witness.checkpoints[0].records[0][field] = "PRIVATE_SENTINEL";
    const result = await run(f);
    assert.equal(check(result, "input").status, "FAIL");
    assert.equal(f.requests.length, 0);
    assert.doesNotMatch(JSON.stringify(result), /PRIVATE_SENTINEL/);
  }
});

test("matching root, owner, certification and bytes pass their checks; missing inclusion fails overall", async () => {
  const f = fixture();
  const result = await run(f);
  assert.equal(result.ok, false);
  for (const id of [
    "input",
    "sui-root",
    "owner-binding",
    "certification",
    "manifest-hash",
    "record-hash",
    "freshness",
  ])
    assert.equal(check(result, id)?.status, "PASS", id);
  assert.equal(check(result, "record-inclusion")?.code, "RECORD_INCLUSION_UNPROVEN");
  assert.equal(check(result, "record-inclusion")?.status, "FAIL");
  assert.equal(f.requests.at(-1).url, PUBLIC_ENDPOINTS.sui);
  assert.match(JSON.parse(f.requests.at(-1).init.body).query, /query latest/);
});

test("an unrelated available blob with its own correct hash cannot produce PASS", async () => {
  const f = fixture();
  f.input.record.walrusBlobId = blobId(5);
  f.input.record.ciphertextCommitment = hash("unrelated record");
  const prior = f.fetch;
  f.fetch = async (url, init) =>
    url.endsWith(blobId(5)) ? new Response("unrelated record") : prior(url, init);
  const result = await run(f);
  assert.equal(check(result, "record-hash").status, "PASS");
  assert.equal(result.ok, false);
  assert.equal(check(result, "record-inclusion").code, "RECORD_INCLUSION_UNPROVEN");
});

for (const [name, alter, id] of [
  [
    "missing root",
    (f) => {
      f.responses.changes.transaction.effects.objectChanges.nodes = [];
    },
    "sui-root",
  ],
  [
    "wrong package",
    (f) => {
      f.responses.changes.transaction.effects.objectChanges.nodes[0].outputState.asMoveObject.contents.type.repr =
        rootType.replace("5bbc", "6bbc");
    },
    "sui-root",
  ],
  [
    "failed transaction",
    (f) => {
      f.responses.transaction.transaction.effects.status = "FAILURE";
    },
    "sui-root",
  ],
  [
    "different transaction",
    (f) => {
      f.responses.transaction.transaction.digest = "4".repeat(44);
    },
    "sui-root",
  ],
  [
    "different root version",
    (f) => {
      f.fields.root_version = "111";
    },
    "sui-root",
  ],
  [
    "different root commitment",
    (f) => {
      f.fields.root_commitment = object("f");
    },
    "sui-root",
  ],
  [
    "different checkpoint commitment",
    (f) => {
      f.fields.checkpoint_commitment = object("f");
    },
    "sui-root",
  ],
  [
    "different manifest pointer",
    (f) => {
      f.fields.checkpoint_manifest_blob_id = Buffer.from(blobId(6)).toString("base64");
    },
    "sui-root",
  ],
  [
    "different manifest hash",
    (f) => {
      f.fields.checkpoint_manifest_ciphertext_commitment = object("f");
    },
    "sui-root",
  ],
  [
    "wrong owner",
    (f) => {
      f.fields.owner_ref_commitment = object("f");
    },
    "owner-binding",
  ],
  [
    "wrong account",
    (f) => {
      f.fields.memwal_account_id = object("f");
    },
    "owner-binding",
  ],
  [
    "wrong account owner",
    (f) => {
      f.fields.account_owner_address = object("f");
    },
    "owner-binding",
  ],
  [
    "wrong policy",
    (f) => {
      f.fields.policy_epoch = "2";
    },
    "owner-binding",
  ],
  [
    "wrong schema",
    (f) => {
      f.fields.schema_version = 2;
    },
    "owner-binding",
  ],
  [
    "wrong network",
    (f) => {
      f.fields.network = 1;
    },
    "owner-binding",
  ],
  [
    "missing event",
    (f) => {
      f.responses.events.transaction.effects.events.nodes = [];
    },
    "certification",
  ],
  [
    "wrong event package",
    (f) => {
      f.responses.events.transaction.effects.events.nodes[0].contents.type.repr = eventType.replace(
        "5bbc",
        "6bbc",
      );
    },
    "certification",
  ],
  [
    "wrong event account",
    (f) => {
      f.event.memwal_account_id = object("f");
    },
    "certification",
  ],
  [
    "wrong event commitment",
    (f) => {
      f.event.root_commitment = object("f");
    },
    "certification",
  ],
  [
    "wrong event checkpoint",
    (f) => {
      f.event.checkpoint_commitment = object("f");
    },
    "certification",
  ],
  [
    "wrong transaction checkpoint",
    (f) => {
      f.responses.transaction.transaction.effects.checkpoint.sequenceNumber = "1235";
    },
    "certification",
  ],
  [
    "wrong predecessor version",
    (f) => {
      f.event.previous_root_version = "108";
    },
    "certification",
  ],
  [
    "superseded",
    (f) => {
      f.responses.latest.object.asMoveObject.contents.json.root_version = "111";
    },
    "freshness",
  ],
  [
    "latest commitment changed",
    (f) => {
      f.responses.latest.object.asMoveObject.contents.json.root_commitment = object("f");
    },
    "freshness",
  ],
  [
    "latest wrong package",
    (f) => {
      f.responses.latest.object.asMoveObject.contents.type.repr = rootType.replace("5bbc", "6bbc");
    },
    "freshness",
  ],
  [
    "latest missing",
    (f) => {
      f.responses.latest.object = null;
    },
    "freshness",
  ],
  [
    "latest changed object version",
    (f) => {
      f.responses.latest.object.version = "123456789012345679";
    },
    "freshness",
  ],
  [
    "latest different transaction",
    (f) => {
      f.responses.latest.object.previousTransaction.digest = "4".repeat(44);
    },
    "freshness",
  ],
  [
    "missing certification time",
    (f) => {
      f.responses.transaction.transaction.effects.timestamp = null;
    },
    "freshness",
  ],
  [
    "future certification time",
    (f) => {
      f.responses.transaction.transaction.effects.timestamp = "2026-11-04T03:06:00.000Z";
    },
    "freshness",
  ],
  [
    "expired certification time",
    (f) => {
      f.responses.transaction.transaction.effects.timestamp = "2026-11-03T02:59:59.000Z";
    },
    "freshness",
  ],
])
  test(`FAIL: ${name}`, async () => {
    const f = fixture();
    alter(f);
    const result = await run(f);
    assert.equal(result.ok, false);
    assert.equal(check(result, id)?.status, "FAIL", JSON.stringify(result));
  });

for (const [name, alter] of [
  [
    "private facts",
    (f) => {
      f.input.ownerFacts = [{ text: "PRIVATE_SENTINEL" }];
    },
  ],
  [
    "nested credentials",
    (f) => {
      f.input.record.secret = "PRIVATE_SENTINEL";
    },
  ],
  [
    "arbitrary endpoint",
    (f) => {
      f.input.graphqlUrl = "https://example.com";
    },
  ],
  [
    "mainnet",
    (f) => {
      f.input.network = "mainnet";
    },
  ],
  [
    "unsafe version",
    (f) => {
      f.input.root.version = Number.MAX_SAFE_INTEGER + 1;
    },
  ],
  [
    "non-integer checkpoint",
    (f) => {
      f.input.root.certification.checkpoint = 1.5;
    },
  ],
  [
    "unknown root field",
    (f) => {
      f.input.root.ownerEmail = "PRIVATE_SENTINEL";
    },
  ],
  [
    "owner mismatch",
    (f) => {
      f.input.record.ownerRef = `simiri-owner-v1:${"b".repeat(64)}`;
    },
  ],
  [
    "patch belongs to different blob",
    (f) => {
      f.input.record.walrusQuiltPatchId = patchId(blobId(7));
    },
  ],
  [
    "invalid blob length",
    (f) => {
      f.input.record.walrusBlobId = "B".repeat(44);
    },
  ],
  [
    "URL as blob",
    (f) => {
      f.input.record.walrusBlobId = "https://example.com/PRIVATE_SENTINEL";
    },
  ],
])
  test(`reject before network: ${name}`, async () => {
    const f = fixture();
    alter(f);
    const result = await run(f);
    assert.equal(result.ok, false);
    assert.equal(check(result, "input").status, "FAIL");
    assert.equal(f.requests.length, 0);
    assert.doesNotMatch(JSON.stringify(result), /PRIVATE_SENTINEL/);
  });

test("quilt patch selected instead of whole quilt", async () => {
  const f = fixture({ patch: true });
  assert.equal(check(await run(f), "record-hash").status, "PASS");
  assert.ok(
    f.requests.some((r) =>
      r.url.endsWith(`/by-quilt-patch-id/${f.input.record.walrusQuiltPatchId}`),
    ),
  );
});

for (const [name, mutate] of [
  [
    "noncanonical blob padding bits",
    (f) => {
      f.input.record.walrusBlobId = blobId(0).slice(0, -1) + "B";
    },
  ],
  [
    "unsupported patch version",
    (f) => {
      f.input.record.walrusQuiltPatchId = patchId(f.input.record.walrusBlobId, 0);
    },
  ],
  [
    "empty patch range",
    (f) => {
      f.input.record.walrusQuiltPatchId = patchId(f.input.record.walrusBlobId, 1, 2, 2);
    },
  ],
  [
    "reversed patch range",
    (f) => {
      f.input.record.walrusQuiltPatchId = patchId(f.input.record.walrusBlobId, 1, 3, 2);
    },
  ],
])
  test(`reject malformed BCS locator: ${name}`, async () => {
    const f = fixture();
    mutate(f);
    const result = await run(f);
    assert.equal(check(result, "input").status, "FAIL");
    assert.equal(f.requests.length, 0);
  });

test("wrong bytes fail even when aggregator returns200", async () => {
  const f = fixture();
  const fetch = f.fetch;
  f.fetch = (url, init) =>
    url.startsWith(PUBLIC_ENDPOINTS.walrus) ? new Response("tampered") : fetch(url, init);
  const result = await run(f);
  assert.equal(check(result, "record-hash").status, "FAIL");
  assert.equal(check(result, "manifest-hash").status, "FAIL");
});

test("latest read failure fails freshness; response/error body never echoed", async () => {
  const f = fixture();
  const fetch = f.fetch;
  f.fetch = async (url, init) =>
    init.body?.includes("query latest")
      ? Promise.reject(new Error("PRIVATE_SENTINEL"))
      : fetch(url, init);
  const result = await run(f);
  assert.equal(check(result, "freshness").status, "FAIL");
  assert.doesNotMatch(formatReport(result), /PRIVATE_SENTINEL/);
});

test("bounded pagination includes root/event on later pages", async () => {
  const f = fixture();
  const fetch = f.fetch;
  f.fetch = async (url, init) => {
    if (init.body) {
      const { query, variables } = JSON.parse(init.body);
      const field = query.includes("query changes")
        ? "objectChanges"
        : query.includes("query events")
          ? "events"
          : null;
      if (field && variables.after === null)
        return Response.json({
          data: {
            transaction: {
              effects: {
                [field]: { nodes: [], pageInfo: { hasNextPage: true, endCursor: "page2" } },
              },
            },
          },
        });
    }
    return fetch(url, init);
  };
  const result = await run(f);
  assert.equal(check(result, "sui-root").status, "PASS");
  assert.equal(check(result, "certification").status, "PASS");
});

test("pagination cycle fails instead of silently truncating", async () => {
  const f = fixture();
  f.responses.events.transaction.effects.events.pageInfo = { hasNextPage: true, endCursor: "same" };
  const result = await run(f);
  assert.equal(check(result, "certification").status, "FAIL");
  assert.ok(f.requests.length < 15);
});

for (const scenario of [
  "redirect",
  "graphql-error",
  "invalid-json",
  "too-large",
  "unbounded-stream",
  "body-timeout",
])
  test(`transport fails closed: ${scenario}`, async () => {
    const fetch = async (_url, init) => {
      if (scenario === "redirect")
        return new Response("", {
          status: 302,
          headers: { location: "https://example.com/PRIVATE_SENTINEL" },
        });
      if (scenario === "graphql-error")
        return Response.json({ errors: [{ message: "PRIVATE_SENTINEL" }] });
      if (scenario === "invalid-json") return new Response("PRIVATE_SENTINEL");
      if (scenario === "too-large")
        return new Response("", { headers: { "content-length": String(20 * 1024 * 1024) } });
      return new Response(
        new ReadableStream({
          start(controller) {
            if (scenario === "unbounded-stream")
              controller.enqueue(new Uint8Array(3 * 1024 * 1024));
            init.signal.addEventListener(
              "abort",
              () => controller.error(new Error("PRIVATE_SENTINEL")),
              { once: true },
            );
          },
        }),
      );
    };
    const transport = publicTransport({ fetch, timeoutMs: 20 });
    await assert.rejects(
      transport.graphql("transaction", { digest }),
      (error) => !error.message.includes("PRIVATE_SENTINEL"),
    );
  });

for (const [status, headers] of [
  [500, {}],
  [302, { location: "https://example.com" }],
  [200, { "content-length": "999999999" }],
])
  test(`early HTTP refusal cancels the unread body (${status})`, async () => {
    let cancelled = false;
    let requestSignal;
    const transport = publicTransport({
      fetch: async (_url, init) => {
        requestSignal = init.signal;
        return new Response(
          new ReadableStream({
            cancel() {
              cancelled = true;
            },
          }),
          { status, headers },
        );
      },
    });
    await assert.rejects(transport.graphql("transaction", { digest }));
    assert.equal(cancelled, true);
    assert.equal(requestSignal.aborted, true);
  });

test("all failure reports use fixed codes without owner ref, facts, response bodies or credentials", async () => {
  const f = fixture();
  const result = await run(f);
  const report = formatReport(result);
  assert.match(report, /^FAIL\n/);
  assert.doesNotMatch(report, /simiri-owner|PRIVATE_SENTINEL|accountOwner/);
  assert.match(report, /FAIL record-inclusion RECORD_INCLUSION_UNPROVEN/);
});

test("CLI uses bounded local JSON, rejects bad usage/private inputs without requests", async () => {
  const dir = await mkdtemp(join(tmpdir(), "simiri-public-verifier-"));
  try {
    const file = join(dir, "input.json");
    await writeFile(file, JSON.stringify({ ownerFacts: "PRIVATE_SENTINEL" }));
    const io = {
      output: "",
      stdout: {
        write(s) {
          io.output += s;
        },
      },
      stderr: {
        write(s) {
          io.output += s;
        },
      },
    };
    assert.equal(await main([file], io), 1);
    assert.doesNotMatch(io.output, /PRIVATE_SENTINEL/);
    for (const args of [
      [],
      [file, "--graphql-url", "https://example.com"],
      [file, "--max-age-hours", "Infinity"],
      [file, "--max-age-hours", "0"],
    ])
      assert.equal(await main(args, io), 2);
    await writeFile(file, "PRIVATE_SENTINEL");
    assert.equal(await main([file], io), 2);
    await writeFile(file, "x".repeat(17 * 1024 * 1024));
    assert.equal(await main([file], io), 2);
    assert.doesNotMatch(io.output, /PRIVATE_SENTINEL/);
  } finally {
    await rm(dir, { recursive: true });
  }
});

test("CLI reads the witness file and reports PASS/exit0, then a missing ref gives FAIL/exit1", async () => {
  const dir = await mkdtemp(join(tmpdir(), "simiri-public-verifier-cli-"));
  const originalFetch = globalThis.fetch;
  try {
    const f = witnessFixture();
    f.responses.transaction.transaction.effects.timestamp = new Date(
      Date.now() - 3_600_000,
    ).toISOString();
    globalThis.fetch = f.fetch;
    const file = join(dir, "synthetic-public-witness.json");
    const io = {
      output: "",
      stdout: {
        write(s) {
          io.output += s;
        },
      },
      stderr: {
        write(s) {
          io.output += s;
        },
      },
    };
    await writeFile(file, JSON.stringify(f.input));
    assert.equal(await main([file], io), 0);
    assert.match(io.output, /^PASS\n/);
    assert.doesNotMatch(io.output, /simiri-owner|subject-1/);
    f.input.record.recordId = "not-present";
    await writeFile(file, JSON.stringify(f.input));
    io.output = "";
    assert.equal(await main([file], io), 1);
    assert.match(io.output, /^FAIL\n/);
  } finally {
    globalThis.fetch = originalFetch;
    await rm(dir, { recursive: true });
  }
});
