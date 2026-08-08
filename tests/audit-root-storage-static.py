#!/usr/bin/env python3
"""Safe, unprivileged/static checks for the fixed progressive root-storage audit.

Covers: fixed no-argument verb and exact sudo boundary, embedded scanner
syntax, redaction, symlink/mount safety, per-subtree and global over-limit
behavior, partial-result markers, depth and time bounds, bounded top-N
report, deterministic hard-link accounting, and generated installer
integrity.  Race checks are asserted structurally because they need the
real /proc mount inventory and privileged trusted paths.
"""
from __future__ import annotations

import hashlib
import os
import pathlib
import re
import subprocess
import sys
import tempfile
from typing import Any, Callable, cast

ROOT = pathlib.Path(__file__).resolve().parents[1]
helper = (ROOT / "src/vds-guardianctl").read_text(encoding="utf-8")
sudoers = (ROOT / "src/vds-guardian.sudoers").read_text(encoding="utf-8")
upgrade = (ROOT / "templates/upgrade-existing.sh.in").read_text(encoding="utf-8")

# --- Fixed no-argument helper verb and exact sudo boundary are unchanged. ---
assert "audit-root-storage) audit_root_storage ;;" in helper
assert helper.count("audit-root-storage) audit_root_storage ;;\n") == 1
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

# --- Extract and compile the embedded scanner. ---
match = re.search(
    r"audit_root_storage\(\) \{\n.*?/usr/bin/python3 - <<'PY'\n(.*?)\nPY\n\}",
    helper,
    re.DOTALL,
)
assert match, "embedded scanner not found"
scanner = match.group(1)
compile(scanner, "embedded-audit-root-storage.py", "exec")

# --- Fixed bounds, safety invariants, and progressive markers. ---
for required in (
    "ROOT=b'/root'",
    "SUBTREE_MAX_ENTRIES=",
    "GLOBAL_MAX_ENTRIES=",
    "MAX_DEPTH=64",
    "MAX_SECONDS=120",
    "MAX_REPORT=8388608",
    "TOP_N=",
    "LIST_MAX=",
    "O_NOFOLLOW",
    "b'/proc/self/mountinfo'",
    "LOCK_EX|fcntl.LOCK_NB",
    "follow_symlinks=False",
    "st_blocks*512",
    "mount boundary inventory changed during audit",
    "directory changed during traversal",
    "object crossed an unrecorded mount boundary",
    "status='partial'",
    "not_audited",
    "excluded path=%s reason=mount",
):
    assert required in scanner, required
for forbidden in ("readlink", "listxattr", "getxattr", "setxattr", "os.walk", "subprocess"):
    assert forbidden not in scanner, forbidden
assert "str(e)" not in scanner
assert "except OSError as" not in scanner
assert "self.files=set()" in scanner
assert "self.category_files=" in scanner
assert "category=%s size=%d status=%s" in scanner

# --- Load definitions without executing main(). ---
namespace: dict[str, object] = {"__name__": "audit_static_test"}
exec(scanner.rsplit("try:main()", 1)[0], namespace)
shown = cast(Callable[[bytes], str], namespace["shown"])
categories = cast(Callable[[bytes], set[str]], namespace["categories"])
unescape = cast(Callable[[bytes], bytes], namespace["unescape"])
Scanner = cast(Any, namespace["Scanner"])
Bad = cast(Any, namespace["Bad"])
SubtreeLimit = cast(Any, namespace["SubtreeLimit"])
GlobalLimit = cast(Any, namespace["GlobalLimit"])
Names = cast(Callable[..., list[bytes]], namespace["names"])
audit = cast(Callable[..., bytes], namespace["audit"])

# --- Redaction and category classification units. ---
assert shown(b"project-1") == "project-1"
for sensitive in (b".ssh", b"api_token", b"passwords", b"client.key", b"vault", b"bad\nname", b"unicode-\xff"):
    assert shown(sensitive) == "<redacted>"
assert unescape(b"/root/a\\040b") == b"/root/a b"
assert "cache" in categories(b"pip-cache")
assert "backups" in categories(b"database.tar.gz")
assert "logs" in categories(b"server.log")
assert "temp" in categories(b"scratch.tmp")

# --- Directory enumeration failure stays generic. ---
try:
    Names(999999, lambda: None, lambda: None)
except Bad as error:
    assert str(error) == "directory enumeration failed"
else:
    raise AssertionError("invalid directory descriptor did not fail generically")

# --- Deterministic hard-link accounting (one charge per object total, one per category). ---
with tempfile.TemporaryDirectory() as directory:
    root = os.fsencode(directory)
    first = root + b"/cache-file"
    second = root + b"/server.log"
    with open(first, "wb") as stream:
        stream.write(b"x")
    os.link(first, second)
    allocated = os.stat(first).st_blocks * 512
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        scan = Scanner(set(), os.fstat(fd).st_dev)
        one = scan.node(fd, b"cache-file", first, "/root/cache-file", 1, set())
        two = scan.node(fd, b"server.log", second, "/root/server.log", 1, set())
        assert one["size"] == allocated
        assert two["size"] == 0
        assert scan.totals["cache"] == allocated
        assert scan.totals["logs"] == allocated
        # Per-subtree budget stops enumeration with a SubtreeLimit.
        namespace["SUBTREE_MAX_ENTRIES"] = 1
        bounded = Scanner(set(), os.fstat(fd).st_dev)
        try:
            Names(fd, bounded.reserve_sub, bounded.check)
        except SubtreeLimit:
            pass
        else:
            raise AssertionError("bounded directory enumeration accepted too many names")
        finally:
            namespace["SUBTREE_MAX_ENTRIES"] = 250000
    finally:
        os.close(fd)


def run_audit(builder: Callable[[pathlib.Path], None], mounts: set[bytes] | None = None, **patched: Any) -> str:
    """Run the embedded audit() against a fresh temp tree with patched bounds."""
    saved = {k: namespace[k] for k in patched}
    namespace.update(patched)
    try:
        with tempfile.TemporaryDirectory() as directory:
            builder(pathlib.Path(directory))
            fd = os.open(os.fsencode(directory), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                return audit(fd, set() if mounts is None else mounts).decode("ascii")
            finally:
                os.close(fd)
    finally:
        namespace.update(saved)


def completed_lines(report: str) -> list[str]:
    out = []
    for line in report.splitlines():
        if line.startswith("category="):
            break
        if line.startswith("path="):
            out.append(line)
    return out


# --- Redaction, symlink safety, categories, and a fully completed run. ---
def base_tree(root: pathlib.Path) -> None:
    (root / "project").mkdir()
    (root / "project" / "cache").mkdir()
    (root / "project" / "password-token").write_bytes(b"x")
    (root / "backups").mkdir()
    (root / "token-dir").mkdir()
    (root / "outside-link").symlink_to("/etc/shadow")
    (root / "server.log").write_bytes(b"y")


report = run_audit(base_tree)
assert "audit=root-storage progressive=1" in report
assert "summary completed=5 partial=0 excluded=0 not_audited=0 " in report
assert "path=/root/<redacted> " in report  # token-dir is redacted
assert "password-token" not in report  # child names are never reported
assert "server.log" in report
assert "/etc/shadow" not in report  # symlink target is never followed or read
assert "type=symlink" in report
for line in completed_lines(report):
    assert "status=complete" in line and "reason=" not in line
for category in ("cache", "backups", "Git", "logs", "temp"):
    assert f"category={category} size=" in report
    assert f"category={category} size=" in report and "status=complete" in report
assert "status=partial" not in report
assert "not_audited path=" not in report
assert "limit=" not in report

# --- Per-subtree over-limit: the giant subtree is partial, others complete. ---
def many_files(root: pathlib.Path) -> None:
    (root / "big").mkdir()
    for i in range(12):
        (root / "big" / f"f{i:02d}").write_bytes(b"x")
    (root / "small").mkdir()


report = run_audit(many_files, SUBTREE_MAX_ENTRIES=5)
lines = completed_lines(report)
assert "path=/root/big " in report
assert "path=/root/small " in report
big_line = next(line for line in report.splitlines() if line.startswith("path=/root/big "))
small_line = next(line for line in report.splitlines() if line.startswith("path=/root/small "))
assert "status=partial" in big_line and "reason=entry_limit" in big_line and "entries=" in big_line
assert "status=complete" in small_line and "reason=" not in small_line
assert "summary completed=1 partial=1 " in report
assert "category=cache size=0 status=partial" in report  # categories are partial, not exact

# --- Global over-limit: later subtrees are explicitly not audited. ---
def three_trees(root: pathlib.Path) -> None:
    for name in ("a", "b", "c"):
        (root / name).mkdir()
        for i in range(8):
            (root / name / f"f{i:02d}").write_bytes(b"x")


report = run_audit(three_trees, GLOBAL_MAX_ENTRIES=12)
assert "not_audited path=/root/c" in report
assert "limit=entry_limit" in report
assert "summary completed=1 partial=1 excluded=0 not_audited=1 " in report
b_line = next(line for line in report.splitlines() if line.startswith("path=/root/b "))
assert "status=partial" in b_line and "reason=global_entry_limit" in b_line

# --- Time budget: a zero/negative deadline fails the whole run with markers. ---
report = run_audit(base_tree, MAX_SECONDS=-1)
assert "summary completed=0 partial=0 excluded=0 not_audited=unbounded " in report
assert "limit=time_limit" in report

# --- Depth bound: too-deep subtrees are partial, never exact. ---
def deep_chain(root: pathlib.Path) -> None:
    target = root / "chain"
    for i in range(6):
        target = target / f"d{i}"
    target.mkdir(parents=True)


report = run_audit(deep_chain, MAX_DEPTH=3)
chain_line = next(line for line in report.splitlines() if line.startswith("path=/root/chain "))
assert "status=partial" in chain_line and "reason=depth_limit" in chain_line
assert "summary completed=0 partial=1 " in report

# --- Bounded top-N summary: only the largest completed subtrees are reported. ---
def sized_dirs(root: pathlib.Path) -> None:
    for i in range(5):
        (root / f"d{i}").mkdir()
    (root / "d0" / "big").write_bytes(b"x" * 100000)


report = run_audit(sized_dirs, TOP_N=2)
completed = [line for line in completed_lines(report) if "status=complete" in line]
assert len(completed) == 2
assert any(line.startswith("path=/root/d0 ") for line in completed)
assert "path=/root/d2 " not in report
assert "path=/root/d3 " not in report
assert "path=/root/d4 " not in report
assert "summary completed=5 " in report

# --- Top-level mount boundary is excluded and reported, never followed. ---
def with_mount(root: pathlib.Path) -> None:
    (root / "mnt").mkdir()
    (root / "data").mkdir()
    (root / "data" / "f").write_bytes(b"x")


report = run_audit(with_mount, mounts={b"/root/mnt"})
assert "excluded path=/root/mnt reason=mount" in report
assert "summary completed=1 partial=0 excluded=1 " in report
assert "category=cache size=0 status=partial" in report  # excluded mount contents are unknown

# --- Nested mount inside a subtree makes that subtree partial. ---
def nested_mount(root: pathlib.Path) -> None:
    (root / "sub").mkdir()
    (root / "sub" / "mnt").mkdir()
    (root / "sub" / "keep").mkdir()


report = run_audit(nested_mount, mounts={b"/root/sub/mnt"})
sub_line = next(line for line in report.splitlines() if line.startswith("path=/root/sub "))
assert "status=partial" in sub_line and "reason=mount" in sub_line

# --- Generated installer integrity: dist embeds the reviewed source and
# --- SHA256SUMS verifies the regenerated installers byte-for-byte. ---
build = subprocess.run(
    [sys.executable, str(ROOT / "tools/build.py")],
    cwd=ROOT,
    capture_output=True,
    text=True,
)
assert build.returncode == 0, build.stderr
for name in ("install-new.sh", "install-existing.sh", "upgrade-existing.sh"):
    text = (ROOT / "dist" / name).read_text(encoding="utf-8")
    assert "audit=root-storage progressive=1" in text
    assert "SUBTREE_MAX_ENTRIES=250000" in text
    assert text.count("# vds-guardianctl-sha256: " + digest) >= 1
checksum = subprocess.run(["sha256sum", "-c", "SHA256SUMS"], cwd=ROOT, capture_output=True, text=True)
assert checksum.returncode == 0, checksum.stderr

print("audit_root_storage_static_ok")
