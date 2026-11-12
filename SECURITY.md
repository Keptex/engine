# Security policy

The Keptex engine is the deterministic credential derivation layer of the Keptex project. Because
the algorithm is the entire trust layer, we treat security disclosure with the
highest priority. This document describes scope, the threat model, the
responsible-disclosure policy, and what is explicitly out of scope.

The cryptographic specification lives in [ALGORITHM.md](ALGORITHM.md); the Stellar
Root and Ledger Sync contract between the client and the Soroban contract lives in
[docs/LEDGER-SYNC.md](docs/LEDGER-SYNC.md).

---

## Scope

This policy covers the four packages published in this repository:

- `@keptex/core`: password derivation and the optional second-factor mode, Web
  Crypto only, zero runtime dependency.
- `@keptex/passkey`: WebAuthn passkey derivation, depends only on `@noble/curves`.
- `@keptex/stellar-root`: SEP-53 Stellar Root, strict Ed25519 verification,
  signature normalisation, determinism checks, SEP-23 strkeys.
- `@keptex/ledger-sync`: Ledger Identity, signed payloads of the KeptexSyncRegistry
  contract, sync envelope, sequence choice.

All are source-available under the [PolyForm Noncommercial License 1.0.0](LICENSE).

The Soroban contract has its own repository and policy,
[Keptex/sync-registry](https://github.com/Keptex/sync-registry); a finding that
spans both can be reported to either. The wider Keptex product (vault, wallet
connectors, relayer, applications) is developed separately and is not in scope
here.

---

## Threat model summary

Keptex assumes the user controls a cryptographic wallet (imported or native) and
the device the engine runs on. The wallet's signing key is the only secret in the
system; the engine stores no secret material at rest. Passwords and passkey
private keys are re-derived per use from a 64-byte `userKey` held in RAM for the
session. The `userKey` is derived once per session via PBKDF2 (100 000 iterations)
over a wallet signature for imported wallets, or via HKDF over the BIP-39 seed for
native wallets. All derivations are HMAC-SHA-256 based with explicit domain
separators (`com.keptex.authentication`, `com.keptex.password`,
`com.keptex.passkey`, `com.keptex.credentialId`, and for Ledger Sync
`com.keptex.ledger.v1` and `com.keptex.sync-envelope.v1`), so the same `userKey`
produces statistically independent outputs.

In the default `key-only` mode, derivation is **single-factor by design**: loss or
compromise of the wallet results in loss or compromise of every credential. This
is the deliberate non-custodial trade-off. The optional `key-plus-secret` mode mixes
a 256-bit secret key into `userKey`, so that the wallet alone no longer suffices:
neither a leaked wallet key nor a phished root signature regenerates a
credential, the Ledger Identity or the sync-envelope key. What the mode covers,
what it does not (a compromised device, the wallet and the recovery code in the
same hands, the place where the code is saved) and its trade-off (without the
recovery code the vault cannot be rebuilt on another device) are in
[ALGORITHM.md](ALGORITHM.md), section 11.1. The mode was reviewed internally on
2026-11-12; it has not been audited by a third party.

For Stellar wallets, `@keptex/stellar-root` adds three guarantees before a
signature reaches the engine: it is a SEP-53 signature of the authentication
message, it verifies under the connected address with the `verify_strict` rules
of ed25519-dalek (the verifier of the Soroban host), and it is deterministic
(two signatures compared at sign-up, then `R` compared on every unlock). The
signature is the root secret: it is never logged and never placed in an error
message.

`@keptex/ledger-sync` only ever publishes an envelope encrypted with AES-256-GCM
under a key derived from `userKey`, bound to the Ledger Identity and to the
sequence; the contract accepts exactly the next sequence, so a lying read path can
neither lock an identity nor pass an old envelope off as current.

---

## Responsible disclosure

**Please report security vulnerabilities privately, not via public issues.**

- **Email:** `security@keptex.com` *(if the dedicated mailbox is not yet live,
  email `contact@keptex.com` with `[SECURITY]` in the subject)*
- **Expected initial response:** within 7 calendar days.
- **Coordinated disclosure window:** 90 days from acknowledgement, negotiable in
  good faith for issues that need downstream coordination.
- **Public credit:** reporters are credited unless they request anonymity.

### What to include

- A clear description of the vulnerability and its impact
- Affected component (package name and version, or `main` at commit SHA)
- A minimal reproduction (script, test vector, or written walk-through)
- Your severity assessment

---

## Out of scope

- **Third-party wallets.** Vulnerabilities in any imported wallet live with those
  projects. The engine's interface is the published `Signer` contract
  (`identifier()` and `sign(message)`); any wallet that implements it correctly is
  integrated correctly from our side. A wallet or provider that signs whatever it
  is given controls the root: the root is exactly as strong as the account behind
  it.
- **The host operating system and browser.** A fully compromised device defeats
  every software wallet, including Keptex. We do not claim to defend against full
  device compromise, keyloggers, or screen capture.
- **Quantum adversaries.** Ed25519 and ES256 are not post-quantum; this is
  inherited from the wallet ecosystems and from WebAuthn itself.

**Long-term confidentiality of Ledger Sync.** What is written to the blockchain
is permanent: `remove` deletes the envelope from the current state of the
contract, not from the history of the chain, so an adversary can archive every
version of a block today and try to open it later. The cipher, AES-256-GCM, is
considered safe against quantum computers. The weak point is the key
derivation: without a second factor, the key derives from the wallet's Ed25519
private key, which a large enough quantum computer could recover from the public
address, and which a thief of the wallet key already holds. With the random
secret key of the `key-plus-secret` mode, the wallet key alone derives neither
the Ledger Identity nor the envelope key
(`packages/ledger-sync/tests/second-factor.test.ts`, with a `key-only` control
where the same attack succeeds). The rule for clients, implemented by
`syncPolicy` in `@keptex/ledger-sync`: Ledger Sync is allowed with a random
secret key, not offered in `key-only` mode (or only behind an explicit
warning), and refused when the secret is derived from a master password, since
the public, permanent block lets an attacker guess the password offline without
limit. See [docs/LEDGER-SYNC.md](docs/LEDGER-SYNC.md), section 9.

---

## Known limitations and trust assumptions

Documented honestly so auditors and integrators can assess the trade-offs:

- **No external audit yet.** The algorithm is documented and reproducible from
  the public test vectors, and `@keptex/core` is zero-dependency Web Crypto, but no
  independent firm has reviewed any package. An audit is the top priority.
- **Internal audit of 2026-11-11.** `@keptex/stellar-root` and
  `@keptex/ledger-sync` were reviewed internally before publication. Its findings
  are addressed in this code: the contract and the client accept exactly the next
  sequence (an inflated sequence from a lying read used to lock an identity); the
  sequence is in the envelope AAD (an old envelope could be served as current); `R`
  is compared across sessions (a wallet that caches a randomised signature per
  session passed the in-session check); public keys are decoded as ed25519-dalek
  decodes them; provider error text is no longer copied into errors. The envelope
  reader now rejects a byte order mark and repeated JSON keys, and the `@noble`
  dependencies are pinned to exact versions.
- **The signing message is fixed (phishing of the root).** Any site connected to
  the same wallet can ask the user to sign the Keptex authentication message and
  obtain the root, hence, in `key-only` mode, every credential. The wallet shows the
  requesting origin, and the message states its purpose and carries the line
  `Only sign this inside the Keptex extension or app, never on a website.`,
  but in `key-only` mode the defence is the user's: approve this message only inside a
  Keptex surface. The control is the second-factor mode: with it the signature
  alone derives nothing (tests in `packages/ledger-sync/tests/second-factor.test.ts`). In `raw-hash` mode (embedded wallets) the user does not even
  see the message, hence not the warning either.
- **Variable-time verification.** Stellar Root verifies the signature, which is a
  secret, in variable time (BigInt arithmetic), locally and once per unlock; it is
  not exposed to remote timing.
- **Table-based AES.** `@keptex/ledger-sync` uses the pure JavaScript AES-GCM of
  `@noble/ciphers`, because `crypto.subtle` is not guaranteed on every target; see
  its README for the cache-timing note.
- **Public metadata.** A Ledger Sync user's identity pseudonym, write times,
  sequence and envelope size in 1 024-byte steps are public on the ledger, and a
  removal does not erase the encrypted envelopes kept in the ledger history:
  every version ever written stays readable in encrypted form, which is why
  Ledger Sync is restricted by security mode (threat model summary above).
- **Constant-time guarantees are best-effort.** Web Crypto primitives are
  constant-time under the browser's implementation; the JavaScript glue is not.
- **Forward secrecy across sessions is intentionally not provided.** Deterministic
  derivation is the defining property; rotation is achieved by bumping the
  per-service `counter`, which produces a fresh credential.
- **Side-channel resistance of `@noble/curves`** (used by `@keptex/passkey`) is
  inherited from upstream; Trail of Bits audited the library in 2023 and 2024.

---

## CVE history

No CVEs have been issued as of this writing. Future advisories will be listed here
with a CVE ID, affected versions, severity, summary, and a link to the patched
release.
