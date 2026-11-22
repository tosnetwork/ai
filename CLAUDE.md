# Working in this repository

## One module

The repository is a single Go module, `github.com/tosnetwork/ai`. Do not add
nested `go.mod` files to the component directories. Run `make verify` at the
root before proposing a change; do not rely on CI as the verification.

## Boundaries

`spec/`, `protocol/`, `gateway/`, `execution/`, `messenger/` and `provider/`
are separate components, and the programs built from them stay separate
processes.

- `gateway/` must not import `execution/`.
- `protocol/` must import neither `gateway/` nor `execution/`.
- `messenger/` may import `protocol/` only.
- `provider/` may import `protocol/` and `execution/` only.
- No component imports `messenger/` or `provider/`.

`make boundary-lint` enforces these rules. Go's `internal/` rule keeps each
component's internal packages private to it.

## Component rules

Each directory keeps its own `CLAUDE.md` or `AGENTS.md` where it has one, and
those rules apply to work inside it in addition to these. The specification is
normative: make schema changes in `spec/` first.

## Frozen data

Test vectors, golden files, fixtures and the evidence records in
`spec/deployments/` are hash-pinned. Never regenerate or rewrite them as a side
effect of another change.

## Conventions

- Comments explain intent, not history; no tracker references or external
  project names in comments or commit messages.
- Errors are handled explicitly and carry enough context to act on.
