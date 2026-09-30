#!/usr/bin/env python3
"""Compose the M0 org Gitleaks baseline with an optional repo-level config.

A --config file replaces Gitleaks' default rules unless it extends something.
Repo configs in this org use `[extend] useDefault = true` plus allow-lists.
This script rewrites that to `[extend] path = <org baseline>` so EVM rules
always apply and repo allow-lists still win on duplicate rule IDs.

Repo files may only add allow-lists. A copied or replaced rule would drop
the org baseline for that id, so `rules` is rejected.
"""

from __future__ import annotations

import os
import pathlib
import re
import sys
import tomllib

ALLOWED_TOP_LEVEL = {"title", "description", "extend", "allowlist", "allowlists"}
USE_DEFAULT_TRUE = re.compile(
    r"^[ \t]*useDefault[ \t]*=[ \t]*true[ \t]*(?:#[^\n]*)?$",
    re.MULTILINE,
)
USE_DEFAULT_ANY = re.compile(
    r"^[ \t]*useDefault[ \t]*=",
    re.MULTILINE,
)


def fail(message: str) -> int:
    print(f"ERROR: {message}", file=sys.stderr)
    return 1


def validate_repo_config(text: str, repo_path: pathlib.Path) -> int | None:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        return fail(f"{repo_path} is not valid TOML: {exc}")

    if not isinstance(data, dict):
        return fail(f"{repo_path} must be a TOML table")

    extra = sorted(set(data) - ALLOWED_TOP_LEVEL)
    if extra:
        return fail(
            f"{repo_path} may only contain allow-lists "
            f"(rejected keys: {', '.join(extra)})"
        )

    extend = data.get("extend", {})
    if extend is None:
        extend = {}
    if not isinstance(extend, dict):
        return fail(f"{repo_path} [extend] must be a table")
    unexpected = sorted(set(extend) - {"useDefault"})
    if unexpected:
        return fail(
            f"{repo_path} [extend] may only set useDefault = true "
            f"(rejected: {', '.join(unexpected)})"
        )
    if "useDefault" in extend and extend["useDefault"] is not True:
        return fail(f"{repo_path} must set useDefault = true")
    return None


def main() -> int:
    org_path = pathlib.Path(os.environ["ORG_CONFIG"]).resolve()
    repo_path = pathlib.Path(os.environ["REPO_CONFIG"])
    out_path = pathlib.Path(os.environ["EFFECTIVE_CONFIG"])

    if not org_path.is_file():
        return fail(f"org Gitleaks config missing: {org_path}")

    if not repo_path.is_file():
        out_path.write_text(org_path.read_text(encoding="utf-8"), encoding="utf-8")
        print(f"using org baseline only ({org_path})")
        return 0

    text = repo_path.read_text(encoding="utf-8")
    rejected = validate_repo_config(text, repo_path)
    if rejected is not None:
        return rejected

    org_abs = str(org_path)
    replacement = f'path = "{org_abs}"'
    true_lines = USE_DEFAULT_TRUE.findall(text)
    any_lines = USE_DEFAULT_ANY.findall(text)
    if len(any_lines) != len(true_lines) or len(true_lines) > 1:
        return fail(f"{repo_path} must contain a single `useDefault = true`")
    if true_lines:
        text, n = USE_DEFAULT_TRUE.subn(replacement, text, count=1)
        if n != 1:
            return fail(f"{repo_path} has useDefault but not `useDefault = true`")
    elif re.search(r"^\[extend\]", text, re.MULTILINE):
        text = re.sub(
            r"^\[extend\]",
            f"[extend]\n{replacement}",
            text,
            count=1,
            flags=re.MULTILINE,
        )
    else:
        text = f"[extend]\n{replacement}\n\n{text}"

    out_path.write_text(text, encoding="utf-8")
    print(f"composed {repo_path} extending org baseline")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
