# Ledger Sync and Stellar Root, normative specification (v1)

Status: v1, revised 2026-11-11 after the first implementation pass (strict verification defined, sequence read, versioned scope, dedicated sync envelope). This document is the single contract between the TypeScript packages `@keptex/stellar-root` and `@keptex/ledger-sync` (repository [Keptex/engine](https://github.com/Keptex/engine)) and the Soroban contract KeptexSyncRegistry (repository [Keptex/sync-registry](https://github.com/Keptex/sync-registry)). Both sides implement it independently and must produce byte-identical payloads and signatures for the shared test vectors. Any change here is a breaking change and bumps the version tags below.

## 1. Stellar Root (wallet signature, SEP-53)

- The signed message is the authentication message that `@keptex/core` passes to `signer.sign()`, UTF-8 encoded. Stellar Root never builds its own message.
- SEP-53 hash: `hash = SHA-256( UTF-8("Stellar Signed Message:\n") || message )`, 32 bytes.
- Signature: Ed25519 over `hash`, 64 bytes. Verification uses the public key decoded from the connected G-address (SEP-23 strkey, version byte `6 << 3`, CRC16-XModem checksum, little-endian checksum bytes). Verification follows the `verify_strict` semantics of `ed25519-dalek`, which the Soroban host uses: cofactorless equation `[S]B = R + [k]A`, `S` canonical (`S < L`), `R` accepted only if it equals byte for byte the canonical encoding of `[S]B - [k]A`, `A` decoded as dalek decodes it (a non-canonical y-coordinate encoding of a point that is not of small order is accepted, as the Soroban host does), and both `A` and `R` rejected when of small order. Implementations must match this behaviour exactly; ZIP-215 or cofactored verification is non-conformant.
- Accepted signature encodings, normalised to 64 raw bytes before verification: raw `Uint8Array(64)`; hexadecimal of 128 characters, upper or lower case digits, optionally prefixed by a lowercase `0x` (an uppercase `0X` is rejected); canonical standard base64 of 88 characters with `==` padding (RFC 4648 alphabet, unused bits zero; the URL-safe alphabet is rejected). Anything else is rejected. Normalisation never guesses: a string that matches none of these shapes is an error.
- Two signing modes:
  - `wallet`: the wallet receives the message and applies SEP-53 itself (Varial, Stellar Wallets Kit modules, WalletConnect `stellar_signMessage`).
  - `raw-hash`: the provider receives the 32-byte SEP-53 hash and signs it raw (Privy `signRawHash`, hash passed as `0x`-prefixed hex).
- In both modes the returned signature is verified against the address and the SEP-53 hash before it reaches the derivation engine. A failed verification is an error, never a fallback.
- Determinism check at sign-up: the message is signed twice and both normalised signatures must be byte-identical; otherwise the root is refused. Implementations expose it as an explicit option, enabled by the sign-up flow and off for routine unlocks (it costs a second wallet prompt).
- Determinism across sessions: two signatures in one session can match while a wallet with a random nonce merely caches its answer. At sign-up the client stores `R`, the first 32 bytes of the signature (public, it reveals nothing about `S` or the derived key), and every later unlock refuses a signature whose `R` differs.
- Error messages never carry provider text or any signature bytes: only an error code and the provider's error name.
- Known limit, reduced but not removed: the message is fixed (it depends on the account and the mode, not on the requesting site), so any site connected to the same wallet can ask the user to sign it and obtain the root. The wallet shows the requesting origin, and the message itself carries the line `Only sign this inside the Keptex extension or app, never on a website.`. That line is a warning, not a control: a user who approves the message on a website still hands over the root. This risk is stated in the threat model; a reminder in the applications' own interface comes with the connectors.

## 2. Ledger Identity

- `seed = HMAC-SHA-256( key = userKey (64 bytes), data = UTF-8("com.keptex.ledger.v1") )`, 32 bytes. The scope carries a version so that a future change of derivation is explicit.
- Ed25519 key pair from `seed` as the RFC 8032 private key. `identity` = the 32-byte public key.
- The identity has no Stellar account and never signs a transaction. It only signs the payloads below.

## 3. Contract address encoding inside payloads

- `contract` = the XDR encoding of the contract address as an `ScVal`: `0x00000012` (SCV_ADDRESS) || `0x00000001` (SC_ADDRESS_TYPE_CONTRACT) || 32-byte contract id. Total 40 bytes. This is what `Address::to_xdr(&env)` returns for a contract address in the Soroban SDK; the Rust side must assert the 40-byte shape in a test.

## 4. Signed payloads

All integers are big-endian. `||` is concatenation. Tags are UTF-8 without terminator.

- Publish: `"keptex.sync.publish.v1" || contract (40) || identity (32) || seq (u64, 8) || SHA-256(envelope) (32)`
- Remove: `"keptex.sync.remove.v1" || contract (40) || identity (32) || seq (u64, 8)`
- Signature: Ed25519 by the Ledger Identity over the raw payload bytes (no pre-hash), 64 bytes.

## 5. Contract rules (KeptexSyncRegistry)

- `publish(identity: BytesN<32>, seq: u64, envelope: Bytes, sig: BytesN<64>)`:
  - `envelope` in the section 6 format: first byte `0x01` and length `33 + 1024 * k` with `1 <= k <= 15` (1 057 to 15 393 bytes, within the 16 384-byte absolute bound). Enforcing the format on-chain makes a fake identity cost the price of a real one and keeps every stored envelope padded;
  - `seq` exactly equal to the last sequence ever accepted for `identity` (publish or remove) plus one, so the first write uses 1. An exact increment, rather than "strictly greater", prevents a signed call with an inflated sequence (for instance `u64::MAX`, obtained from a lying read) from locking an identity forever, and limits what a withheld signed call can do;
  - signature verified with `env.crypto().ed25519_verify` over the publish payload rebuilt on-chain;
  - writes `Record { seq, envelope, created_at, updated_at, returned }` (ledger timestamps; `created_at` set on the first write of the identity) in persistent storage under the identity, extends its TTL, increments `total_publishes` and, the first time an identity ever publishes, `total_identities`; the first time an identity publishes at least 86 400 seconds after its `created_at`, sets `returned` and increments `total_returning`; emits `SyncPublished { identity, seq, envelope_len }`.
- `remove(identity, seq, sig)`: same exact-increment rule, signature over the remove payload; deletes the envelope but keeps the last accepted sequence (tombstone), so an older signed publish can never be replayed after a removal; emits `SyncRemoved { identity, seq }`.
- `get(identity) -> Option<Record>`, `last_seq(identity) -> u64` (the last sequence ever accepted, publish or remove, 0 if none, so a new device can continue after a removal) and `stats() -> Stats { total_identities, total_publishes, total_returning }`: public reads. `total_returning` counts identities that came back at least a day after their creation: it is the counter a reviewer should trust most, because inflating it costs two publishes a day apart per fake identity.
- No administrator, no upgrade entry point, no constructor-held secrets. A next version is a new contract.
- Anyone may submit a valid signed call; the relayer is a convenience, not an authority.
- Storage layout, which a client reading with `getLedgerEntries` relies on: one persistent entry per identity, key `ScVal::Bytes(identity)`, value a map `{ created_at, envelope, returned, seq, updated_at }`. After a removal the entry stays with an empty `envelope` and the `seq` of the removal (tombstone): a client must read an empty envelope as "removed". Counters live in instance storage under `Symbol("stats")`.
- `remove` on an identity with no published envelope (never published, or already removed) fails with `NotFound` and creates nothing.
- Typed errors (stable codes): 1 `EnvelopeEmpty`, 2 `EnvelopeTooLarge`, 3 `SequenceZero`, 4 `SequenceMismatch`, 5 `NotFound`, 6 `EnvelopeMalformed`.
- An invalid signature aborts the call in the host (`Error(Crypto, InvalidInput)`), not as a typed contract error. Cheap checks (lengths, sequence, presence) run first, so a call with both a stale sequence and a bad signature reports the sequence error.
- Entry TTL: a new persistent entry starts at the network minimum (`min_persistent_ttl`, 120 days on mainnet on 2026-11-11), so the first publish pays that much rent; each write extends the entry to at least 30 days, at most once a day, capped by the network maximum, which only matters once the initial period has run down. The relayer extends active entries beyond that. An archived entry is restored, never reset, so the tombstone survives.
- Rent and resource fee of a first publish, measured on 2026-11-11 with mainnet parameters (floor rent rate of 1 000 stroops per KB, 120-day minimum TTL, entry = envelope + 247 bytes): 0.218 XLM for k = 1 (1 057 bytes), 0.389 XLM for k = 2, 0.730 XLM for k = 4, 2.608 XLM for k = 15 (15 393 bytes, about 7.93 XLM a year). A replacement publish costs about 0.0012 XLM. The rent rate rises if the Soroban state grows past its target.
- Events: topics `[Symbol("sync_published" | "sync_removed"), Bytes(identity)]`, data `{ seq: u64, envelope_len: u32 }` for a publish and `{ seq: u64 }` for a removal. Sequences have no gaps under the exact-increment rule.

## 6. Sync envelope (client side, opaque to the contract)

The metadata backup file of `@keptex/vault-core` is not reused on the ledger: its header exposes counters in clear and the same key opens a backup file. The sync envelope is a separate format:

- `envelopeKey = HMAC-SHA-256( key = userKey, data = UTF-8("com.keptex.sync-envelope.v1") )`, 32 bytes, used only for sync envelopes.
- Plaintext: with `json` the compact UTF-8 JSON metadata and `n = len(json)`, `n >= 1`: `plaintext = u32be(n) || json || 0x00 * (1024 * ceil(n / 1024) - n)`, so `len(plaintext) = 4 + 1024 * k`. On opening, the length, the zero padding, the UTF-8 and the JSON are all checked. No count, date or identifier outside the ciphertext.
- Resulting size: `len(envelope) = 33 + 1024 * k`, so at most 15 360 bytes of JSON (k = 15). The JSON schema of the synchronised metadata is not fixed by this version: it is set before the first client ships (full service entries fit about 38 to an envelope, reduced entries about 174).
- `envelope = 0x01 (format version) || nonce (12 random bytes) || AES-256-GCM( envelopeKey, nonce, plaintext, aad )`, with `aad = UTF-8("keptex.sync.envelope.v1") || identity (32) || seq (u64, 8)`, so an envelope cannot be replayed under another identity, nor served as current under a later sequence. The client encrypts for the sequence it is about to sign and opens with the `seq` of the record it read.
- The total stays within the 16 384-byte contract bound; the client refuses to publish otherwise.

## 7. Sequence choice on the client

- Before publishing or removing, the client reads `last_seq(identity)` and uses `last_seq + 1`, the only value the contract accepts. Two devices racing on the same value: one transaction fails on the sequence rule, that device reads again and retries with a fresh envelope encrypted for the new sequence.

## 8. Shared test vector inputs

Both implementations compute the outputs from these inputs and record them; the two sets must match byte for byte.

- `userKey` = bytes `0x00, 0x01, …, 0x3f` (64 bytes).
- `contractId` = 32 bytes of `0x11`.
- `seq` = 1 for publish, 2 for remove.
- `envelope` = UTF-8 `"keptex-ledger-sync-test-envelope-v1"`.
- Outputs to record (hex, lowercase): `ledgerSeed`, `identity`, `contractScVal`, `publishPayload`, `publishSignature`, `removePayload`, `removeSignature`.

## 9. Long-term confidentiality

This section is a client policy. It changes no payload, no signature, no contract rule and no test vector.

### 9.1 Threat model

- **Permanence.** What is written to the ledger is permanent. `remove` deletes the envelope from the current state (section 5) but not from the history of the chain: every earlier `publish`, with its envelope, remains readable in past ledgers, and each new version of the block is a new public copy. Nothing in this contract, and nothing a client can do, erases it. The reference attack is therefore "harvest now, decrypt later": an adversary archives every envelope today and opens it whenever the key becomes available to them.
- **The cipher is not the weak point.** The envelope is sealed with AES-256-GCM (section 6), considered safe against quantum computers (a quantum adversary gains at best a factor of two on the effective key size, by Grover's algorithm). No claim is made about what future computing will do beyond that.
- **The key derivation is.** Without a second factor, `userKey` is `PBKDF2(signature)`, and the Ledger Identity (section 2) and the `envelopeKey` (section 6) are HMACs of it. The signature is a deterministic Ed25519 function of the wallet private key and a fixed message. Ed25519 is vulnerable to Shor's algorithm and wallet addresses are public, so an adversary with a sufficiently large quantum computer could recover the private key from the address, recompute the signature, derive the identity and the envelope key, locate every archived block and open all versions. A thief of the wallet key is in the same position as that adversary for this question.
- **With a random Secret Key (`key-plus-secret`)**, the final `userKey` is `HKDF(baseUserKey, salt = secretKey)` with a random 256-bit secret that is neither on the chain nor in the wallet. An adversary who holds the wallet private key can recompute `baseUserKey` but not `userKey`: they can neither derive the identity (so cannot find the record), nor the envelope key (so cannot open a block). `packages/ledger-sync/tests/second-factor.test.ts` demonstrates it, with a control in `key-only` where the same attack succeeds. This holds only if the identity and the envelope key are derived from the **final** `userKey` (secret included), never from the base key; a client must pass the final `userKey` to `deriveLedgerIdentity` and to the envelope functions.
- **With a master password (`key-plus-password`)**, the secret is derived from the password. The block being public forever, an adversary can test password guesses offline for as long as they like, at the cost of one Argon2id and one HKDF per guess. The protection is bounded by the entropy of the password and does not match the property above.
- **Without a second factor (`key-only`)**, there is no protection against an adversary able to recover the wallet private key.
- **What stays public in every mode** (section 6 and the security notes of ALGORITHM.md section 12.6): the identity pseudonym, the write times, the sequence numbers and the envelope size in 1 024-byte steps.

### 9.2 Requirements for every client

1. A client MUST derive the Ledger Identity and the envelope key from the final `userKey`, and MUST NOT enable Ledger Sync unless it holds a verdict from `syncPolicy(securityMode)` of `@keptex/ledger-sync`, which implements the rules below.
2. **`key-plus-secret`: allowed.** This is the only mode in which Ledger Sync can be enabled without a warning.
3. **`key-only`: the client does not offer the option.** This is the recommended behaviour and the default of `syncPolicy`. A client MAY instead offer the option as a tolerated variant, only behind the warning of section 9.4 and an explicit confirmation (a deliberate action that is not the default focus; the text is shown in full, not collapsed, before the confirmation is possible). `syncPolicy(mode, { keyOnly: 'warn' })` returns `warn` for that variant.
4. **`key-plus-password`: refused.** The client MUST NOT allow activation, whatever the strength of the password, and MUST show the refusal message of section 9.4.
5. **Any other value, or no value: refused.** A missing or unrecognised mode is never read as allowed.
6. A client that enables Ledger Sync MUST tell the user, before the first publish, that `remove` does not erase the history and that successive versions of the block remain public. The texts of section 9.4 already say it; a client that words it differently MUST keep the same facts.
7. The mode is fixed at the creation of the vault (ALGORITHM.md section 11.1); the threat model of this section is also in ALGORITHM.md section 11.2. A vault in `key-only` or `key-plus-password` cannot be turned into a `key-plus-secret` vault: the user creates a new vault, which changes every credential.

### 9.3 What a publish contains

Today the metadata that a client synchronises (section 6) is whatever the client chooses to put in the JSON; the extension stores service names, usernames, counters and passkey metadata. All of it becomes permanent public history, in encrypted form, at the first publish.

### 9.4 Texts

The texts are exported as `SYNC_POLICY_MESSAGES` by `@keptex/ledger-sync` and are normative for English clients; a translation MUST keep the same facts. They promise no more than the property described in 9.1: they do not say that data is "safe", "unbreakable" or "quantum-proof".

Warning, `key-only`, tolerated variant (`key-only-warning`):

> Ledger Sync keeps an encrypted copy of your service list on the public Stellar blockchain. Everything written there stays public forever, including older versions and anything you later delete. In this vault, the encryption key can be recomputed from your wallet’s private key. Today that key is private. If it were ever stolen or broken, for example by future quantum computers, anyone who saved a copy of the blockchain could read every version ever written. Turn on Ledger Sync only if you accept this. A vault created with a Secret Key does not have this limit.

Not offered, `key-only`, default (`key-only-unavailable`), shown only where the client explains why the option is absent:

> Ledger Sync is not available for this vault. It publishes an encrypted copy of your service list that stays public forever, and in this vault mode the key protecting it depends on your wallet’s private key alone. Ledger Sync is available for vaults created with a Secret Key.

Refusal, `key-plus-password` (`key-plus-password-refused`):

> Ledger Sync is not available for vaults protected by a master password. The encrypted copy would stay public forever, so anyone could keep a copy and try passwords against it offline, with no limit on the number of tries and no time limit. A password, however good, is weaker than a random Secret Key. To use Ledger Sync, create a vault with a Secret Key.

Refusal, unknown mode (`unknown-mode-refused`):

> Ledger Sync is not available because the security mode of this vault is not recognised.

### 9.5 Future work

- **Smaller content.** Synchronise only what cannot be recomputed from the vault inputs: non-standard usernames, rotation counters and hand-typed entries. Service names that follow the standard policy are recomputable and need not be published.
- **Fingerprint only.** Publish a fingerprint of the metadata (a hash, or an encrypted pointer) on the ledger and keep the data in a storage the user chooses (own server, file, cloud account). The ledger then proves integrity and order without holding the content. This changes the envelope format and the contract rules and is therefore a new version.
