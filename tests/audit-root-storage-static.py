#!/usr/bin/env python3
"""Safe, unprivileged/static checks for the fixed root-storage audit."""
from __future__ import annotations

import hashlib
import os
import pathlib
import re
import tempfile
from typing import Any, Callable, cast

ROOT = pathlib.Path(__file__).resolve().parents[1]
helper = (ROOT / "src/vds-guardianctl").read_text(encoding="utf-8")
sudoers = (ROOT / "src/vds-guardian.sudoers").read_text(encoding="utf-8")
upgrade = (ROOT / "templates/upgrade-existing.sh.in").read_text(encoding="utf-8")

assert "audit-root-storage) audit_root_storage ;;" in helper
assert helper.count("audit-root-storage) audit_root_storage ;;") == 1
verb = "/usr/local/sbin/vds-guardianctl audit-root-storage"
assert sudoers.count(verb) == 1
assert verb + " " not in sudoers

digest = hashlib.sha256(helper.encode()).hexdigest()
assert sudoers.splitlines().count(f"# vds-guardianctl-sha256: {digest}") == 1

# The only newly accepted upgrade baseline is the exact source pair from
# 304d084, and rollback compares both restored leaves to that selected pair.
baseline_helper = "26a83ff99dfd63640b0a14d069fdeb0a8235b1c80fefa4d8168d6d3064084fbc"
baseline_sudoers = "d656075f924c9d5b047fa75c8072cdf99e399220b4e858fd435a36e492fb8004"
assert hashlib.sha256((ROOT / "tests/fixtures/vds-guardianctl-304d084").read_bytes()).hexdigest() == baseline_helper
assert hashlib.sha256((ROOT / "tests/fixtures/vds-guardian.sudoers-304d084").read_bytes()).hexdigest() == baseline_sudoers
assert f"readonly BASELINE_V5_HELPER_SHA256='{baseline_helper}'" in upgrade
assert f"readonly BASELINE_V5_SUDOERS_SHA256='{baseline_sudoers}'" in upgrade
assert '"$selected_baseline_helper_sha256  $HELPER_PATH"' in upgrade
assert '"$selected_baseline_sudoers_sha256  $SUDOERS_PATH"' in upgrade

match = re.search(
    r"audit_root_storage\(\) \{\n.*?/usr/bin/python3 - <<'PY'\n(.*?)\nPY\n\}",
    helper,
    re.DOTALL,
)
assert match, "embedded scanner not found"
scanner = match.group(1)
compile(scanner, "embedded-audit-root-storage.py", "exec")

# The scanner has no path/argument/environment override and uses fixed bounds.
for required in (
    "ROOT=b'/root'",
    "MAX_ENTRIES=500000",
    "MAX_DEPTH=64",
    "MAX_SECONDS=120",
    "MAX_REPORT=8388608",
    "O_NOFOLLOW",
    "b'/proc/self/mountinfo'",
    "LOCK_EX|fcntl.LOCK_NB",
    "follow_symlinks=False",
    "st_blocks*512",
    "mount boundary inventory changed during audit",
):
    assert required in scanner, required
for forbidden in ("readlink", "listxattr", "getxattr", "setxattr", "os.walk", "subprocess"):
    assert forbidden not in scanner, forbidden
assert "str(e)" not in scanner
assert "except OSError as" not in scanner
assert "self.files=set()" in scanner
assert "self.category_files=" in scanner

# Load definitions without executing main(), then exercise control-safe redaction,
# mountinfo escaping, and fixed category classification.
namespace: dict[str, object] = {"__name__": "audit_static_test"}
exec(scanner.rsplit("try:main()", 1)[0], namespace)
shown = cast(Callable[[bytes], str], namespace["shown"])
categories = cast(Callable[[bytes], set[str]], namespace["categories"])
unescape = cast(Callable[[bytes], bytes], namespace["unescape"])
assert shown(b"project-1") == "project-1"
for sensitive in (b".ssh", b"api_token", b"passwords", b"client.key", b"vault", b"bad\nname", b"unicode-\xff"):
    assert shown(sensitive) == "<redacted>"
assert unescape(b"/root/a\\040b") == b"/root/a b"
assert "cache" in categories(b"pip-cache")
assert "backups" in categories(b"database.tar.gz")
assert "logs" in categories(b"server.log")
assert "temp" in categories(b"scratch.tmp")

# Hard-linked regular-file blocks are charged deterministically only to the
# first sorted object, while each independently applicable category gets one
# charge. Directory enumeration itself is bounded before sorting.
Scanner = cast(Any, namespace["Scanner"])
Bad = cast(Any, namespace["Bad"])
Names = cast(Callable[..., list[bytes]], namespace["names"])
try:
    Names(999999, lambda: None, lambda: None)
except Bad as error:
    assert str(error) == "directory enumeration failed"
else:
    raise AssertionError("invalid directory descriptor did not fail generically")
with tempfile.TemporaryDirectory() as directory:
    root = os.fsencode(directory)
    first = root + b"/cache-file"
    second = root + b"/server.log"
    with open(first, "wb") as stream:
        stream.write(b"x")
    os.link(first, second)
    allocated = os.stat(first).st_blocks * 512
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        scan = Scanner(set(), os.fstat(fd).st_dev)
        one = scan.node(fd, b"cache-file", first, "/root/cache-file", 1, set())
        two = scan.node(fd, b"server.log", second, "/root/server.log", 1, set())
        assert one["size"] == allocated
        assert two["size"] == 0
        assert scan.totals["cache"] == allocated
        assert scan.totals["logs"] == allocated
        namespace["MAX_ENTRIES"] = 1
        bounded = Scanner(set(), os.fstat(fd).st_dev)
        try:
            Names(fd, bounded.reserve, bounded.check)
        except Bad as error:
            assert str(error) == "root storage audit entry limit exceeded"
        else:
            raise AssertionError("bounded directory enumeration accepted too many names")
        finally:
            namespace["MAX_ENTRIES"] = 500000
    finally:
        os.close(fd)

for category in ("cache", "backups", "Git", "logs", "temp"):
    assert f"category=%s size=%d\\n'%(c,sc.totals[c])" in scanner

print("audit_root_storage_static_ok")
