#!/usr/bin/env python3
"""Compose the M0 org Gitleaks baseline with an optional repo-level config.

A --config file replaces Gitleaks' default rules unless it extends something.
Repo configs in this org use `[extend] useDefault = true` plus allow-lists.
This script rewrites that to `[extend] path = <org baseline>` so EVM rules
always apply and repo allow-lists still win on duplicate rule IDs.
"""

from __future__ import annotations

import os
import pathlib
import re
import sys


def main() -> int:
    org_path = pathlib.Path(os.environ["ORG_CONFIG"]).resolve()
    repo_path = pathlib.Path(os.environ["REPO_CONFIG"])
    out_path = pathlib.Path(os.environ["EFFECTIVE_CONFIG"])

    if not org_path.is_file():
        print(f"org Gitleaks config missing: {org_path}", file=sys.stderr)
        return 1

    if not repo_path.is_file():
        out_path.write_text(org_path.read_text(), encoding="utf-8")
        print(f"using org baseline only ({org_path})")
        return 0

    text = repo_path.read_text(encoding="utf-8")
    org_abs = str(org_path)

    if re.search(r"^path\s*=", text, re.MULTILINE):
        print(
            f"ERROR: {repo_path} already sets [extend].path. "
            "Repo configs must use `useDefault = true` so the org baseline "
            "can be injected. Move extra allow-lists into this file and drop path.",
            file=sys.stderr,
        )
        return 1

    replacement = f'path = "{org_abs}"'
    if re.search(r"^useDefault\s*=", text, re.MULTILINE):
        text, n = re.subn(
            r"^useDefault\s*=\s*true\s*$",
            replacement,
            text,
            count=1,
            flags=re.MULTILINE,
        )
        if n != 1:
            print(
                f"ERROR: {repo_path} has useDefault but not `useDefault = true`.",
                file=sys.stderr,
            )
            return 1
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
