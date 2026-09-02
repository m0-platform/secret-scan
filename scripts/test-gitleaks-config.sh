#!/usr/bin/env bash
# test-gitleaks-config.sh
#
# Verifies the org Gitleaks baseline against testdata/gitleaks fixtures.
# Requires the gitleaks binary on PATH (installs it if missing on Linux/macOS).
#
# Usage: ./scripts/test-gitleaks-config.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ORG_CONFIG="${ROOT}/.github/actions/secret-scan/gitleaks.toml"
VERSION="${GITLEAKS_VERSION:-8.24.2}"

if ! command -v gitleaks >/dev/null 2>&1; then
  echo "installing gitleaks ${VERSION}"
  tmp="$(mktemp -d)"
  os="$(uname -s)"
  arch="$(uname -m)"
  case "$os-$arch" in
    Linux-x86_64)   asset="gitleaks_${VERSION}_linux_x64.tar.gz" ;;
    Linux-aarch64)  asset="gitleaks_${VERSION}_linux_arm64.tar.gz" ;;
    Darwin-arm64)   asset="gitleaks_${VERSION}_darwin_arm64.tar.gz" ;;
    Darwin-x86_64)  asset="gitleaks_${VERSION}_darwin_x64.tar.gz" ;;
    *) echo "unsupported platform: $os $arch" >&2; exit 1 ;;
  esac
  curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${VERSION}/${asset}" \
    | tar -xz -C "$tmp" gitleaks
  export PATH="${tmp}:${PATH}"
fi

fail_dir="${ROOT}/testdata/gitleaks/should-fail"
pass_dir="${ROOT}/testdata/gitleaks/should-pass"
report="$(mktemp)"

echo "==> should-fail (expect evm-32-byte-hex and bare-32-byte-hex)"
gitleaks dir "$fail_dir" --config="$ORG_CONFIG" --exit-code=0 --report-path="$report" --report-format=json --redact
python3 - "$report" <<'PY'
import json, sys
path = sys.argv[1]
findings = json.load(open(path)) or []
rules = {f.get("RuleID") for f in findings}
needed = {"evm-32-byte-hex", "bare-32-byte-hex"}
missing = needed - rules
if missing:
    raise SystemExit(f"missing rule ids {sorted(missing)}; got {sorted(rules)}")
print(f"found {len(findings)} finding(s) covering {sorted(needed)}")
PY

echo "==> should-pass (expect clean)"
if ! gitleaks dir "$pass_dir" --config="$ORG_CONFIG" --exit-code=1 --verbose --redact; then
  echo "ERROR: unexpected findings in ${pass_dir}" >&2
  exit 1
fi

echo "==> compose-config.py rewrites useDefault to org path"
tmp="$(mktemp -d)"
repo_toml="${tmp}/.gitleaks.toml"
effective="${tmp}/effective.toml"
cat > "$repo_toml" <<'TOML'
[extend]
useDefault = true

[allowlist]
description = "repo extra"
regexTarget = "secret"
regexes = ['''^0xdead$''']
TOML
ORG_CONFIG="$ORG_CONFIG" REPO_CONFIG="$repo_toml" EFFECTIVE_CONFIG="$effective" \
  python3 "${ROOT}/.github/actions/secret-scan/compose-config.py"
grep -q "path = \".*gitleaks.toml\"" "$effective"
grep -q "useDefault" "$effective" && { echo "ERROR: useDefault should have been replaced"; exit 1; }
grep -q "0xdead" "$effective"

echo "gitleaks org baseline fixtures passed"
