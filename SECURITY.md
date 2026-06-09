# Security policy

The Keptex engine is the deterministic credential derivation layer of the Keptex project. Because
the algorithm is the entire trust layer, we treat security disclosure with the
highest priority. This document describes scope, the threat model, the
responsible-disclosure policy, and what is explicitly out of scope.

The cryptographic specification lives in [ALGORITHM.md](ALGORITHM.md).

---

## Scope

This policy covers the two packages published in this repository:

- `@keptex/core`: password derivation, Web Crypto only, zero runtime dependency.
- `@keptex/passkey`: WebAuthn passkey derivation, depends only on `@noble/curves`.

Both are source-available under the [PolyForm Noncommercial License 1.0.0](LICENSE).

The wider Keptex product (vault, wallet stack, applications) is developed
separately and is not in scope here.

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
`com.keptex.passkey`, `com.keptex.credentialId`), so the same `userKey` produces
statistically independent password, passkey, and credentialId outputs.

Derivation in this engine is **single-factor by design**: loss or compromise of
the wallet results in loss or compromise of every credential. This is the
deliberate non-custodial trade-off, identical to any other crypto-native product.

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
  integrated correctly from our side.
- **The host operating system and browser.** A fully compromised device defeats
  every software wallet, including Keptex. We do not claim to defend against full
  device compromise, keyloggers, or screen capture.
- **Quantum adversaries.** Ed25519 and ES256 are not post-quantum; this is
  inherited from the wallet ecosystems and from WebAuthn itself.

---

## Known limitations and trust assumptions

Documented honestly so auditors and integrators can assess the trade-offs:

- **No formal external audit yet.** The algorithm is documented and reproducible
  from the public test vectors, and `@keptex/core` is zero-dependency Web Crypto,
  but no independent firm has reviewed it. An audit is the top priority.
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
