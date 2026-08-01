#!/usr/bin/env python3
"""Build self-contained installers from reviewed source files."""

from __future__ import annotations

import hashlib
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
TEMPLATES = ROOT / "templates"
DIST = ROOT / "dist"


def build(template_name: str, output_name: str) -> pathlib.Path:
    template = (TEMPLATES / template_name).read_text(encoding="utf-8")
    helper = (SRC / "vds-guardianctl").read_text(encoding="utf-8").rstrip("\n")
    sudoers = (SRC / "vds-guardian.sudoers").read_text(encoding="utf-8").rstrip("\n")
    replacements = {
        "__HELPER__": helper,
        "__SUDOERS__": sudoers,
        "__NEW_HELPER_SHA256__": hashlib.sha256(
            (helper + "\n").encode("utf-8")
        ).hexdigest(),
        "__NEW_SUDOERS_SHA256__": hashlib.sha256(
            (sudoers + "\n").encode("utf-8")
        ).hexdigest(),
    }
    rendered = template
    for token, value in replacements.items():
        rendered = rendered.replace(token, value)
    if any(token in rendered for token in replacements):
        raise SystemExit(f"unreplaced token in {output_name}")
    output = DIST / output_name
    output.write_text(rendered, encoding="utf-8")
    output.chmod(0o755)
    return output


def main() -> None:
    DIST.mkdir(parents=True, exist_ok=True)
    outputs = [
        build("install-new.sh.in", "install-new.sh"),
        build("install-existing.sh.in", "install-existing.sh"),
        build("upgrade-existing.sh.in", "upgrade-existing.sh"),
    ]
    lines = []
    for output in outputs:
        digest = hashlib.sha256(output.read_bytes()).hexdigest()
        lines.append(f"{digest}  dist/{output.name}\n")
    (ROOT / "SHA256SUMS").write_text("".join(lines), encoding="utf-8")


if __name__ == "__main__":
    main()
