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
# No --redact: the assertions below compare the captured secret to the fixture.
# Do not print that report.
gitleaks dir "$fail_dir" --config="$ORG_CONFIG" --exit-code=0 --report-path="$report" --report-format=json --no-banner >/dev/null
python3 - "$report" <<'PY'
import json, sys
path = sys.argv[1]
findings = json.load(open(path)) or []
rules = {f.get("RuleID") for f in findings}
needed = {"evm-32-byte-hex", "bare-32-byte-hex"}
missing = needed - rules
if missing:
    raise SystemExit(f"missing rule ids {sorted(missing)}; got {sorted(rules)}")
by_file = {}
for f in findings:
    by_file.setdefault(f["File"].rsplit("/", 1)[-1], []).append(f.get("Secret"))
if not by_file.get("NamedKey.sol"):
    raise SystemExit("NamedKey.sol produced no findings")
wrapped_key = "0x" + ("ab" * 32)
typehash = "0x" + ("11" * 32)
if wrapped_key not in by_file.get("WrappedKey.sol", []):
    raise SystemExit("WrappedKey.sol did not flag the wrapped private key")
after = by_file.get("KeyAfterTypehash.sol", [])
if wrapped_key not in after:
    raise SystemExit("KeyAfterTypehash.sol did not flag the private key after the typehash")
if typehash in after:
    raise SystemExit("KeyAfterTypehash.sol flagged the TYPEHASH")
if wrapped_key not in by_file.get("CommentTypehash.sol", []):
    raise SystemExit("CommentTypehash.sol did not flag a TYPEHASH comment")
broadcast = [f for f in findings if f["File"].endswith("broadcast/leaked.env")]
if not broadcast:
    raise SystemExit("broadcast/leaked.env was ignored entirely")
if not any(f.get("RuleID") != "evm-32-byte-hex" for f in broadcast):
    raise SystemExit("broadcast/leaked.env was only caught by the path-skipped hex rule")
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

echo "==> compose-config.py accepts indented useDefault"
indented="${tmp}/indented.toml"
cat > "$indented" <<'TOML'
[extend]
  useDefault = true  # org baseline replaces this
TOML
ORG_CONFIG="$ORG_CONFIG" REPO_CONFIG="$indented" EFFECTIVE_CONFIG="${tmp}/indented-out.toml" \
  python3 "${ROOT}/.github/actions/secret-scan/compose-config.py"
grep -q "useDefault" "${tmp}/indented-out.toml" && { echo "ERROR: indented useDefault left in place"; exit 1; }

expect_reject() {
  local name="$1"
  local body="$2"
  local file="${tmp}/${name}.toml"
  printf '%s\n' "$body" > "$file"
  if ORG_CONFIG="$ORG_CONFIG" REPO_CONFIG="$file" EFFECTIVE_CONFIG="${tmp}/${name}-out.toml" \
    python3 "${ROOT}/.github/actions/secret-scan/compose-config.py"; then
    echo "ERROR: ${name} should have been rejected" >&2
    exit 1
  fi
}

echo "==> compose-config.py rejects rule overrides and useDefault = false"
expect_reject "use-default-false" "$(cat <<'TOML'
[extend]
useDefault = false
TOML
)"
expect_reject "copied-rule" "$(cat <<'TOML'
[extend]
useDefault = true

[[rules]]
id = "evm-32-byte-hex"
regex = '''not-a-key'''
TOML
)"

echo "gitleaks org baseline fixtures passed"
