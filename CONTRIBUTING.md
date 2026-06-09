# Contributing to Keptex Engine

Thank you for considering a contribution. This repository contains the Keptex
derivation engine: `@keptex/core` and `@keptex/passkey`, source-available under the
[PolyForm Noncommercial License 1.0.0](LICENSE). Security review and contributions
to the algorithm are especially welcome.

Note: contributions are accepted under a Contributor License Agreement so the
project can offer commercial integration licences. By opening a pull request you
agree to those terms.

---

## Code language

All code, comments, identifiers, JSDoc, error messages, documentation, and any UI
copy are written in **UK English** (centre, behaviour, optimise, organise, licence
as a noun, license as a verb). Existing content can stay until naturally edited.
Discussion in issues and pull requests can be in any language; the artefacts must
be UK English.

---

## Project conventions

- **ESM only.** Every package has `"type": "module"`.
- **Imports use the `.js` extension on source files**, even in TypeScript
  (required by NodeNext / bundler module resolution):
  ```ts
  import { deriveUserKey } from './algorithm.js'  // correct
  import { deriveUserKey } from './algorithm'     // wrong
  ```
- **TypeScript strict mode**, with `noUncheckedIndexedAccess` and
  `noImplicitOverride`. No `any`: use `unknown` and narrow.
- **Type-only imports are explicit:** `import type { X } from './x.js'`.

### Crypto dependency policy

- `@keptex/core` is **zero runtime dependency** and uses **only** the Web Crypto
  API (`crypto.subtle`). Adding any runtime dependency to `core` must be discussed
  in an issue first.
- `@keptex/passkey` may depend on `@noble/curves` (Trail of Bits audited), because
  Web Crypto cannot import Ed25519 / ES256 keys from raw seeds.
- New cryptographic logic must ship with **at least one fixed test vector** that
  maps known inputs to known outputs, committed as JSON next to the test.

### Testing

- **Unit tests:** `vitest` in every package. Run with `pnpm --filter <pkg> test`.
- Any change to the algorithm must regenerate and commit the test vectors and keep
  every published vector byte-identical unless the change is intentional and
  documented.

---

## The green bar

Before any change lands:

```bash
pnpm typecheck
pnpm test
pnpm build
```

This is non-negotiable. A failing test must be fixed, or skipped with a tracking
issue linked in the comment.

---

## Commit messages

This project follows [Conventional Commits 1.0](https://www.conventionalcommits.org):

```
<type>(<scope>): <short summary>
```

Common types: `feat`, `fix`, `docs`, `refactor`, `test`, `build`, `chore`, `perf`.
The body explains the why, not the what.

---

## Branch and pull-request flow

1. Branch from `main` using `<type>/<short-slug>` (e.g. `fix/passkey-rotation-counter`).
2. Keep pull requests small and focused: one thing per PR.
3. Run the green bar locally before opening the PR.
4. Algorithm-touching changes (`@keptex/core`, `@keptex/passkey`) get extra scrutiny;
   include the reasoning and the updated test vectors.

---

## What not to do without discussion

- **Touch the algorithm** without a written rationale and updated test vectors.
- **Add a new runtime dependency to `@keptex/core`** (Web Crypto only).
- **Commit secrets** of any kind. Double-check before staging.
