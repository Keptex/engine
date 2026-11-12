# Integrating Keptex

This repository is **source-available**, not open source. The code is published
so anyone can read, audit, and evaluate it. It is licensed under the [PolyForm
Noncommercial License 1.0.0](LICENSE), which permits noncommercial use only.

## You need a commercial agreement if you intend to

- Embed any part of this software in a product or service used commercially.
- Ship it inside a wallet, application, or platform offered to end users.
- Use it in production for, or on behalf of, a company.

Auditing, experimenting, research, personal projects, and noncommercial use are
covered by the public licence and need no agreement.

## How to integrate

Commercial and wallet integrations are welcome. They go through a short
integration agreement so we can support you and keep the project sustainably
funded. A paid contribution may apply depending on the integration; the point of
the conversation is to agree on terms, not to create a blocker.

**Get in touch:** contact@keptex.com (subject `[INTEGRATION]`).

Tell us what you are building, the platform (browser extension, mobile, desktop,
web), and the scope you have in mind. We will reply with the integration path and
terms.

## Stellar wallets

A Stellar wallet that signs messages per SEP-53 can check, on its own and without
any agreement, whether it would work as a Keptex root: import the public test key
of [`packages/stellar-root/conformance-vectors.json`](packages/stellar-root/conformance-vectors.json)
(never fund it), sign the `message` of each case, and compare the result with
`signature`. Section 9 of [TEST-VECTORS.md](TEST-VECTORS.md) explains the file.
The Soroban contract used by Ledger Sync is licensed separately, see
[Keptex/sync-registry](https://github.com/Keptex/sync-registry).

## Why this model

Keptex is a credential derivation engine that wallets can embed to offer a native
password and passkey manager. Keeping the code auditable builds the trust a wallet
needs before adopting it; keeping commercial use under agreement funds continued
development, security work, and support.
