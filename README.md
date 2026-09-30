# secret-scan

Public Gitleaks reusable workflow and M0 org baseline.

Public GitHub repositories cannot call reusable workflows in private
[`m0-pipelines`](https://github.com/m0-platform/m0-pipelines). Call this repo instead.

```yaml
jobs:
  secret-scan:
    permissions:
      contents: read
    uses: m0-platform/secret-scan/.github/workflows/secret-scan.yml@main
```

See [`examples/calling-repo-security.yml`](examples/calling-repo-security.yml).

Org baseline: [`.github/actions/secret-scan/gitleaks.toml`](.github/actions/secret-scan/gitleaks.toml)

- `evm-32-byte-hex` — `0x` + 64 hex, any variable name
- `bare-32-byte-hex` — 64 hex without `0x` (lockfiles excluded)

Pin `@main` so rule changes land without a SHA bump in every caller. Protect
`main` (PR + review, no force-push).

Repo-level `.gitleaks.toml` should keep `useDefault = true` (allow-lists only).
Do not copy Launchpad's file into every repo.

Private callers can keep using `m0-pipelines` until that workflow wraps this one.

`testdata/gitleaks/should-fail` is synthetic fixture data for CI. Do not enable a
full `gitleaks git` scan of this repository without ignoring those files.
