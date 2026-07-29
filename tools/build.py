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
    rendered = template.replace("__HELPER__", helper).replace("__SUDOERS__", sudoers)
    if "__HELPER__" in rendered or "__SUDOERS__" in rendered:
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
    ]
    lines = []
    for output in outputs:
        digest = hashlib.sha256(output.read_bytes()).hexdigest()
        lines.append(f"{digest}  dist/{output.name}\n")
    (ROOT / "SHA256SUMS").write_text("".join(lines), encoding="utf-8")


if __name__ == "__main__":
    main()
