# AGENTS.md

This file is for coding agents working in `seamless-auth-rust`, the Seamless Auth server adapter
for Rust and Axum.

## Working Standards (fells-code baseline)

These rules apply to every repository in the fells-code org. Repo-specific
guidance may extend them but must not contradict them.

### Attribution

- Commit and open PRs solely under the repository owner's identity. Never
  commit under an agent or assistant identity.
- Never attribute work to an AI assistant: no `Co-Authored-By: Claude` (or any
  assistant) trailers, no "Generated with" / "Created with Claude" notes, and no
  assistant branding or emoji anywhere in commit messages, PR or issue titles
  and descriptions, changesets, code comments, or docs.

### Comments

- Comment only when the code genuinely needs explaining: a non-obvious reason, a
  gotcha, or an invariant. Never narrate what the code plainly does.

### TODOs

- Every `TODO`/`FIXME` must reference a ticket, e.g. `// TODO(#123): ...`.
  Do not leave a bare TODO. If no ticket exists, create one first.

### Commits & branches

- Conventional Commits (`feat:`, `fix:`, `chore:`, `docs:`, `ci:`, `test:`).
- Descriptive branch names (`feat/...`, `fix/...`); never a `claude/` or other
  tool-generated prefix.

### Public-facing text

- No em dashes in commit messages, code comments, PR or issue text, changesets,
  or docs. Use a comma, parentheses, or a separate sentence.

### Before declaring work done

- All code quality checks must pass before you open a PR or call the work done.
  Run them and report the real output; do not open a PR while any check is failing.
- Match the surrounding code's style, naming, and comment density.

## Checks

| Check | Command |
| --- | --- |
| Format | `cargo fmt --check` |
| Lint | `cargo clippy --all-targets -- -D warnings` (also with `--no-default-features` and `--no-default-features --features native-tls`) |
| Tests | `cargo test` |
| MSRV | `cargo +1.88 test` |
| Conformance | see README, "Conformance" |

The crate targets Rust 1.88 (`rust-version` in `Cargo.toml`), set by jsonwebtoken 11. Do not use
language or standard library features newer than that (CI runs 1.88). `Cargo.lock` is committed
so CI builds what was tested.

## Shape

- `src/adapter.rs`: `Adapter`, the router, the request pipeline, the upstream call, writing replies.
- `src/routes.rs`: manifest routes, credential resolution (with silent refresh), session
  verification, what a cookie-transport body may contain.
- `src/refresh.rs`: refresh sharing (one result per refresh token for 5 seconds, on its own task),
  `POST /refresh`, logout.
- `src/manifest.rs`: parsing, matching, the live and embedded manifest.
- `src/guard.rs`: `require_auth`, `authenticate`, the `User` extractor.
- `src/cookies.rs`, `src/jwt.rs`, `src/jwks.rs`, `src/service_token.rs`: HS256 cookies and service
  tokens, RS256 against the API's JWKS.
- `src/tests/`: unit tests against a fake auth API.
- `conformance/refapp`: the reference app for the conformance suite (`cargo run --example refapp`).
  A test fixture.

## Contract

This crate bridges to the `seamless-auth-api` contract. Behaviour must match the Node adapters in
`fells-code/seamless-auth-server`, the Go adapter in `fells-code/seamless-auth-go`, and the
conformance contract in `fells-code/seamless-cli` (`verify/CONFORMANCE.md`). When they disagree,
the conformance suite is the arbiter: change the suite deliberately, never the adapter quietly.

- Keep dependencies minimal. Adopters audit this code; justify every new dependency in
  `Cargo.toml`.
- Never put `token` or `refreshToken` in a cookie-transport response body.
- Verify every session token against the API's JWKS before issuing a cookie from it.
- Never add a hop-count client IP option. It cannot tell a proxy from a client.
- The default HTTP client follows no redirects: a redirect would carry the service token away.

## Releases

Published to crates.io from a `vX.Y.Z` tag. Pre-1.0: a breaking change is a minor bump, and 1.0 is
a deliberate decision, not a side effect.
