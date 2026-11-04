# Public memory record verifier

Standalone Node24 CLI; no install or third-party dependencies. Copy this folder and run:

```sh
node --max-old-space-size=512 verify.mjs owner-approved-public-witness.json
node --max-old-space-size=512 verify.mjs owner-approved-public-witness.json --max-age-hours 12
node --max-old-space-size=512 --test --test-concurrency=1 verify.test.mjs
```

The first output line is **PASS** or **FAIL**, followed by fixed per-check results.
Exit0 requires every check to pass; exit1 means verification failed; exit2 means
usage or input-file failure. A network failure is a FAIL, not evidence of tampering.
The default age limit is24hours. The report includes the transaction time and root
version only after the freshness check passes. It prints no owner reference,
catalogue, ciphertext or server error body.

## Input and explicit disclosure

An owner must explicitly choose to export a witness for this verification.
**Never export or publish it automatically.** The exporter is a separate reviewed
task and is not included here. No existing private receipt is silently converted.

The witness reveals the **complete opaque reference catalogue**: record and
subject references, kinds, field paths, policy identifiers/epochs, owner-chain
hashes, blob/patch locators, checkpoint links, restore policy and any rebind or
account-transition metadata. These reveal structure and relationships, even
though they do not include record contents. The owner must review that disclosure.
No fact text, amounts, plaintext records, credentials, encryption keys or
decryption material belongs in this input. Unknown fields are rejected.

Only a strict JSON file is accepted (at most16MiB):

```text
{
  network: "testnet",
  ownerRef: "simiri-owner-v1:<64 lowercase hex>",
  account: { accountId: "0x<64 hex>", accountOwnerAddress: "0x<64 hex>" },
  root: {
    objectId: "0x<64 hex>", version: <Simiri root_version>,
    commitment: "sha256:<64 hex>", policyEpoch: <positive integer>,
    certification: {
      transactionDigest: <Sui digest>, checkpoint: <checkpoint sequence number>,
      checkpointCommitment: "sha256:<64 hex>"
    },
    manifest: { blobId: <blob or quilt-patch id>, ciphertextCommitment: "sha256:<64 hex>" }
  },
  record: {
    recordId: <selected opaque id>, ownerRef: <same pseudonymous owner>,
    walrusBlobId: <43-character blob id>,
    walrusQuiltPatchId?: <50-character patch id belonging to that blob>,
    ciphertextCommitment: "sha256:<64 hex>"
  },
  witness: {
    format: 1 | 2,
    restorePolicy: <exact committed allowedRecordKinds/allowedFields>,
    checkpoints: <complete exact committed V1 checkpoint, or V2 full checkpoint then deltas>
  }
}
```

This is a schema illustration, not runnable JSON or live evidence. The exact V1/V2
preimages match `financial-memory-owner-root-core.ts` at8adca4e2a. V1 uses one full
checkpoint, including its original record certification fields. V2 uses the latest
full checkpoint and every following delta, in order (at most17segments and10,000
references total). V2 stored references contain no record certification object.
The selected record is identified by its opaque ID, owner, blob/patch locator and
hash. A receipt without this witness **fails record inclusion**; copying a real
root's certification onto another record cannot produce PASS.

## Checks and trust boundary

- Public Sui RPC must return a successful certifying transaction, exactly one
  output root and matching `RootAdvanced` event from the pinned testnet package.
  Root version, commitments, manifest pointer, checkpoint sequence and owner/account/
  network/policy binding must agree. Simiri `root_version` is distinct from the
  Sui object version; both are checked.
- Catalogue, checkpoint and root commitments are recomputed with the existing
  domain-separated SHA256/canonical JSON algorithms. References and chain order,
  owner binding, record counts, selected membership and ciphertext hash must match.
- The selected ciphertext and encrypted head manifest are downloaded and hashed.
  Plain blobs and version1 BCS quilt patches use their respective aggregator paths.
- The latest root must be readable, have exactly the certified version, commitment,
  object version and transaction, and still match its bindings. An old, future,
  superseded, retired or unreadable root fails. Latest is queried after blob reads.

Only these fixed public endpoints are used, without authentication or redirects:

- [Sui testnet GraphQL RPC](https://graphql.testnet.sui.io/graphql)
- [Walrus testnet aggregator](https://aggregator.walrus-testnet.walrus.space)

No endpoint/package overrides, keys, decryption, database, Simiri server, SDK or
environment loader is present. Reads have byte/page/time limits; a limit is FAIL.
The default request timeout is10seconds and the network verification is bounded
at60seconds. No retries or provider writes occur.

PASS proves the specified ciphertext reference is committed by the specified
current root **as observed through the public RPC**. It does not independently
verify validator checkpoint signatures, Walrus erasure coding/certification,
truth of a fact, successful decryption, real-world identity, catalogue business
completeness, rebind/account-transition execution correctness or restore/grant
permissions. It does not follow successors automatically. Historic testnet roots
and ciphertext remain public; there is no deletion or mainnet operation.

All shipped tests use synthetic fixtures. No live record or grant-row acceptance
is implied by their PASS. Existing repository Vitest discovery excludes `tools/`;
run the explicit whole-file Node command above in CI (CI=true, one512MiB process,
120second external cap). No existing CI configuration is modified in this task.

Post-Walrus follow-up: selective inclusion proofs (for example a publisher Merkle
commitment) so one record can be verified without exposing the catalogue. This
requires a separate reviewed publisher/protocol change.

Official references checked4Nov2026: [Sui GraphQL RPC](https://docs.sui.io/develop/accessing-data/graphql/graphql-rpc),
[Walrus blob reads](https://docs.wal.app/docs/http-api/reading-blobs),
[Walrus quilt HTTP APIs](https://docs.wal.app/docs/http-api/quilt-http-apis).

## Package documentation

[Custody and recovery](CUSTODY.md) · [Public testnet identifiers](TESTNET_IDS.json) · [MIT licence](LICENSE)
