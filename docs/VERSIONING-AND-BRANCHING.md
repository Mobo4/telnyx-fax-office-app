# Versioning and Branching Policy

## Goals
- Keep the currently working office fax app stable and recoverable.
- Isolate commercial/major changes so production operations are not disrupted.
- Make rollback simple with explicit branches and tags.

## Branches
- `main`
  - Stable production line (`1.x`).
  - Only backward-compatible changes and validated fixes.
- `codex/v1-stable`
  - Mirrors stable `1.x` maintenance baseline.
- `codex/v1-known-good`
  - Frozen known-good baseline from commit `0261446`.
- `codex/v2-commercial`
  - Major-version workstream (`2.x`) for commercial stack changes.
- Additional feature branches:
  - Use `codex/...` prefix for scoped work (security, billing, UI, SRE).

## Tags
- `v1.2.0-known-good`
  - Points to known-good baseline commit `0261446`.
- Future stable releases use semantic tags:
  - `v1.3.0`, `v1.3.1`, etc.
- `v2` line tags should include pre-release suffix until production-ready:
  - `v2.0.0-alpha.1`, `v2.0.0-beta.1`, etc.

## Version Number Rules
- `1.x`: current working office system.
- `2.x`: commercial stack evolution.
- Patch (`x.y.Z`) for fixes only.
- Minor (`x.Y.z`) for additive compatible features.
- Major (`X.y.z`) for architectural or breaking changes.

## Safe Rollback Examples
- Roll back to known-good:
  - `git checkout codex/v1-known-good`
  - or `git checkout v1.2.0-known-good`
- Return to stable latest:
  - `git checkout main`

## Release Guardrails
- Do not merge `2.x` breaking changes into `main`.
- Require smoke test pass before tagging stable versions.
- Keep changelog updated for every release-tagged session.
