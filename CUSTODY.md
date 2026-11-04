# Custody and recovery (testnet)

**Service custody, not owner self-custody.** The owner authorizes saves and pairing in Simiri. Simiri derives each account's Ed25519 owner key from its protected master seed and pseudonymous owner reference using HKDF; the owner never holds or signs with that derived key. Account grant/revoke transactions have the derived account key as sender and Simiri's service key as gas sponsor: **both sign**. The publication delegate signs record/root publication; the separately configured storage wallet pays for owned Walrus storage and extension. Recording permission never authorizes spending.

**Encrypt and read.** The app Seal-encrypts locally before encrypted bytes go to Walrus. A permitted native Pass agent holds its own reader key, verifies certification, exact ciphertext hash, owner binding and freshness, obtains Seal shares under the onchain policy, then decrypts locally. Authorized app services can also decrypt. One configured committee object/threshold1 means an internal3of5 committee, not one physical server. The relay receives ciphertext and search vectors; approved app/model/embedding paths can process permitted text, and vectors can reveal semantics. This is not a claim that only the human owner can see plaintext. No MemWal MCP is used.

**Grant and revoke.** Pairing adds the reader delegate before an ACTIVE connection. Stop removes that delegate before recording STOPPED; future authorization must fail closed. Revoke cannot erase plaintext or keys already received. The live lender grant/revoke/410 receipt is a separate purpose-bound database/Arc snapshot proof; the native Stop→denied proof for the approved temporary QA pairing is still OPEN. The original pairing is preserved.

**Renew.** Owner-context relay copies have a known **5-epoch testnet lifetime**. Re-store current records at≤2epochs remaining with overlapping verified copies; alert at≤1or unknown horizon. Owned canonical quilts use a distinct storage-wallet extension policy (30epoch target, renew threshold7). R6 retained natural-wake receipts show recovery/retention work; they do not guarantee indefinite storage or repair all historical content forks.

**Recover.** Start from the certified Sui root, fetch/verify the referenced encrypted Walrus history, decrypt with an authorized reader and restore idempotently into an empty local store. The earlier real-network restore needed a retry and disclosed the historical content fork. The R7.6.4 live empty-store restore is complete: 245/245 certified envelopes verified, with an idempotent second restore. The QA ROOT V2 rebind reached CUTOVER during the 14:00Z natural wake. The new test-owner transition receipt records MOVED at12:32:58.815Z during the 12:30Z natural wake. Loss of Simiri's master seed or required authorized-reader material is not cured by ciphertext availability; this is not a full application disaster-recovery proof. Historical public V1 bindings remain public.

**Current read availability.** Reads on the new successor root 0xf44e…4a4a are currently PENDING at the 14 s budget; rows2/9 remain at risk while the R7.6.5 fix is in progress.

```text
Owner --save / approve pairing / Stop--> Simiri service custody
                                          | derived account key + gas sponsor
                                          +--grant/revoke delegate--> Sui policy
                                          | publication delegate signs
                                          +--certified root----------> Sui
                                          | local Seal encryption
                                          +--ciphertext-------------> Walrus
                                          +--ciphertext + vectors---> SDK relay
Reader's own key --> Sui policy + Seal committee (3/5) --> key shares
Reader <------------ verified Walrus ciphertext ---------+
Reader ---------------- local decrypt / verified restore --> empty store
Storage wallet -------- owned-quilt renew / relay re-store --> overlap
```


Documentation snapshot: 4 November 2026. Supporting acceptance receipts and source bindings are retained privately. Prepared for the scoped public-file review authorized on 4 November; this document creates no new live acceptance.
