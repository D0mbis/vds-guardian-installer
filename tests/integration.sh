#!/bin/bash
set -Eeuo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
IMAGE=${VDS_GUARDIAN_TEST_IMAGE:-debian:12-slim}
DOCKER_RUN=(docker run --rm --cpus=2 --memory=1g --memory-swap=1g --pids-limit=512)

python3 "$ROOT/tools/build.py"
bash -n "$ROOT/src/vds-guardianctl"
bash -n "$ROOT/dist/install-new.sh"
bash -n "$ROOT/dist/install-existing.sh"
bash -n "$ROOT/dist/upgrade-existing.sh"
python3 "$ROOT/tests/audit-root-storage-static.py"
visudo -cf "$ROOT/src/vds-guardian.sudoers"
(cd "$ROOT" && sha256sum -c SHA256SUMS)
bash "$ROOT/tests/mutations.sh"

# Fixtures make shallow CI independent of historical Git objects. When the
# baseline commit is available locally, prove that they are byte-for-byte the
# source artifacts published at that commit.
if git -C "$ROOT" cat-file -e 5a78cb9^{commit} 2>/dev/null; then
  cmp -s <(git -C "$ROOT" show 5a78cb9:src/vds-guardianctl) "$ROOT/tests/fixtures/vds-guardianctl-5a78cb9"
  cmp -s <(git -C "$ROOT" show 5a78cb9:src/vds-guardian.sudoers) "$ROOT/tests/fixtures/vds-guardian.sudoers-5a78cb9"
fi
if git -C "$ROOT" cat-file -e 3d20e7d^{commit} 2>/dev/null; then
  cmp -s <(git -C "$ROOT" show 3d20e7d:src/vds-guardianctl) "$ROOT/tests/fixtures/vds-guardianctl-3d20e7d"
  cmp -s <(git -C "$ROOT" show 3d20e7d:src/vds-guardian.sudoers) "$ROOT/tests/fixtures/vds-guardian.sudoers-3d20e7d"
fi
if git -C "$ROOT" cat-file -e 3de0e74^{commit} 2>/dev/null; then
  cmp -s <(git -C "$ROOT" show 3de0e74:src/vds-guardianctl) "$ROOT/tests/fixtures/vds-guardianctl-3de0e74"
  cmp -s <(git -C "$ROOT" show 3de0e74:src/vds-guardian.sudoers) "$ROOT/tests/fixtures/vds-guardian.sudoers-3de0e74"
fi
if git -C "$ROOT" cat-file -e 16db836^{commit} 2>/dev/null; then
  cmp -s <(git -C "$ROOT" show 16db836:src/vds-guardianctl) "$ROOT/tests/fixtures/vds-guardianctl-16db836"
  cmp -s <(git -C "$ROOT" show 16db836:src/vds-guardian.sudoers) "$ROOT/tests/fixtures/vds-guardian.sudoers-16db836"
fi
if git -C "$ROOT" cat-file -e 304d084^{commit} 2>/dev/null; then
  cmp -s <(git -C "$ROOT" show 304d084:src/vds-guardianctl) "$ROOT/tests/fixtures/vds-guardianctl-304d084"
  cmp -s <(git -C "$ROOT" show 304d084:src/vds-guardian.sudoers) "$ROOT/tests/fixtures/vds-guardian.sudoers-304d084"
fi
if git -C "$ROOT" cat-file -e fc50008^{commit} 2>/dev/null; then
  cmp -s <(git -C "$ROOT" show fc50008:src/vds-guardianctl) "$ROOT/tests/fixtures/vds-guardianctl-fc50008"
  cmp -s <(git -C "$ROOT" show fc50008:src/vds-guardian.sudoers) "$ROOT/tests/fixtures/vds-guardian.sudoers-fc50008"
fi

# Inspection templates must select only reviewed metadata and must never dump
# environment, label maps, config/secret contents, or volume mountpoints.
if grep -En '\{\{[[:space:]]*(json[[:space:]]+)?\.Config\.Env|\{\{[[:space:]]*(json[[:space:]]+)?\.Config\.Labels[[:space:]]*\}\}|\{\{[[:space:]]*(json[[:space:]]+)?\.Labels[[:space:]]*\}\}|\.Configs|\.Secrets|\.Mountpoint' \
  "$ROOT/src/vds-guardianctl" "$ROOT/dist/install-new.sh" "$ROOT/dist/install-existing.sh"; then
  echo 'sensitive Docker inspection template found' >&2
  exit 20
fi
grep -Fq 'compose_project={{printf "%q" (index .Labels "com.docker.compose.project")}} compose_volume={{printf "%q" (index .Labels "com.docker.compose.volume")}} compose_version={{printf "%q" (index .Labels "com.docker.compose.version")}}' "$ROOT/src/vds-guardianctl"
grep -Fq 'compose_project={{printf "%q" (index .Labels "com.docker.compose.project")}} compose_network={{printf "%q" (index .Labels "com.docker.compose.network")}} compose_version={{printf "%q" (index .Labels "com.docker.compose.version")}}' "$ROOT/src/vds-guardianctl"
grep -Fq 'name={{printf "%q" (or (index . "Name") "")}} source={{printf "%q" .Source}}' "$ROOT/src/vds-guardianctl"
! grep -Fq 'name={{printf "%q" .Name}} source={{printf "%q" .Source}}' "$ROOT/src/vds-guardianctl"

run_container_test() {
  local mode=$1
  "${DOCKER_RUN[@]}" -v "$ROOT:/repo:ro" "$IMAGE" bash -lc "
set -Eeuo pipefail
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sudo python3 openssh-client iproute2 >/dev/null
if [[ '$mode' == new ]]; then
  ssh-keygen -q -t ed25519 -N '' -f /tmp/test_guardian_key
  public_key=\$(cat /tmp/test_guardian_key.pub)
  enrollment_token='vg1_0123456789abcdefghijklmnopqrstuvwxyz_A-BCDE'
  printf '%s\\n' \"\$enrollment_token\" >/tmp/enrollment-token
  chmod 600 /tmp/enrollment-token
  bash /repo/dist/install-new.sh --public-key \"\$public_key\" --enrollment-token-file /tmp/enrollment-token >/tmp/install.log
  ! grep -F \"\$enrollment_token\" /tmp/install.log
  test \"\$(cat /home/guardian/.vds-guardian-enrollment)\" = \"\$enrollment_token\"
  test \"\$(stat -c '%U:%G %a' /home/guardian/.vds-guardian-enrollment)\" = 'guardian:guardian 600'
else
  adduser --disabled-password --gecos '' guardian >/dev/null
  bash /repo/dist/install-existing.sh >/tmp/install.log
fi
id guardian
stat -c '%U:%G %a %n' /usr/local/sbin/vds-guardianctl /etc/sudoers.d/vds-guardian
mkdir -p /root/project/cache /root/project/nested/deep /root/project/.git /root/backups /root/token-dir
dd if=/dev/zero of=/root/token-dir/payload bs=1024 count=200 status=none
printf 'DO_NOT_DISCLOSE_CONTENT_9f3c\\n' >/root/project/password-token
chmod 000 /root/project/password-token
printf 'deep secret name and content\\n' >/root/project/nested/deep/api-key
ln -s /etc/shadow /root/outside-link
mkdir -p /root/deep-chain/\$(python3 -c 'print(\"/\".join([\"d\"]*70))')
mkdir -p \$(python3 -c 'print(\" \".join(\"/root/entry-%02d\" % i for i in range(71)))')
sudo -u guardian sudo -n /usr/local/sbin/vds-guardianctl audit-root-storage >/tmp/root-audit.log
grep -F 'audit=root-storage progressive=1' /tmp/root-audit.log
grep -E '^summary completed=[0-9]+ partial=[0-9]+ excluded=[0-9]+ not_audited=[0-9]+ entries=[0-9]+$' /tmp/root-audit.log
! grep -F 'DO_NOT_DISCLOSE_CONTENT_9f3c' /tmp/root-audit.log
! grep -F 'password-token' /tmp/root-audit.log
! grep -F 'api-key' /tmp/root-audit.log
! grep -F '/etc/shadow' /tmp/root-audit.log
grep -E '^path=/root/project size=[0-9]+ status=complete owner=0:0 mode=0[0-7]{3,4} type=directory mtime=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' /tmp/root-audit.log
grep -F 'path=/root/<redacted>' /tmp/root-audit.log
grep -E '^path=/root/deep-chain size_lower_bound=[0-9]+ status=partial owner=0:0 mode=0[0-7]{3,4} type=directory mtime=.* reason=depth_limit entries=[0-9]+$' /tmp/root-audit.log
! grep -F '/root/project/nested/deep' /tmp/root-audit.log
! grep -F 'limit=' /tmp/root-audit.log
test \"\$(grep -c '^path=/root/entry-' /tmp/root-audit.log)\" -le 64
test \"\$(grep -E '^summary ' /tmp/root-audit.log | grep -oE 'completed=[0-9]+' | cut -d= -f2)\" -ge 71
for category in cache backups Git logs temp; do grep -E '^category='\$category' size_lower_bound=[0-9]+ status=partial$' /tmp/root-audit.log; done
grep -E '^category=logs size_lower_bound=[0-9]+ status=partial$' /tmp/root-audit.log
if sudo -u guardian sudo -n /usr/local/sbin/vds-guardianctl audit-root-storage extra >/dev/null 2>&1; then
  echo 'audit-root-storage extra argument unexpectedly accepted' >&2; exit 37
fi
cp /etc/sudoers.d/vds-guardian /tmp/good-sudoers
printf '# vds-guardianctl-sha256: %064d\\n' 0 >>/etc/sudoers.d/vds-guardian
if sudo -u guardian sudo -n /usr/local/sbin/vds-guardianctl audit-root-storage >/tmp/drift-audit.log 2>/tmp/drift-audit.err; then
  echo 'audit-root-storage accepted ambiguous authority' >&2; exit 38
fi
test ! -s /tmp/drift-audit.log
install -o root -g root -m 0440 /tmp/good-sudoers /etc/sudoers.d/vds-guardian
exec {audit_lock_fd}>/run/vds-guardian-audit-root-storage.lock
chmod 0600 /run/vds-guardian-audit-root-storage.lock
flock -n "\$audit_lock_fd"
if sudo -u guardian sudo -n /usr/local/sbin/vds-guardianctl audit-root-storage >/tmp/locked-audit.log 2>/tmp/locked-audit.err; then
  echo 'audit-root-storage ignored its lock' >&2; exit 39
fi
test ! -s /tmp/locked-audit.log
flock -u "\$audit_lock_fd"; exec {audit_lock_fd}>&-
install -o root -g root -m 0755 /repo/tests/fake-docker /usr/bin/docker
rm -f /tmp/fake-docker.commands
sudo -u guardian sudo -n /usr/local/sbin/vds-guardianctl audit-compose-projects >/tmp/compose-audit.log
grep -Fx 'id=\"container-id\" name=\"sample-container\" image=\"sample-image\" state=\"running\" status=\"Up 1 minute\"' /tmp/compose-audit.log
grep -Fx 'id=\"container-id\" name=\"/sample-container\" image=\"sample-image\" image_id=\"sha256:sample-image-id\" state=\"running\" restart_policy=\"unless-stopped\"' /tmp/compose-audit.log
grep -Fx 'compose_project=\"sample-project\nforged=true\" compose_service=\"sample-service\" compose_working_dir=\"/srv/sample\" compose_config_files=\"/srv/sample/compose.yml\" compose_oneoff=\"False\" compose_version=\"2.0.0\"' /tmp/compose-audit.log
grep -Fx 'mount type=\"volume\" name=\"sample-volume\" source=\"/var/lib/docker/volumes/sample-volume/_data\" destination=\"/data\" rw=true' /tmp/compose-audit.log
grep -Fx 'network name=\"sample-network\" id=\"network-id\"' /tmp/compose-audit.log
grep -Fx 'id=\"sample-volume\" name=\"sample-volume\" driver=\"local\" scope=\"local\" internal=n/a' /tmp/compose-audit.log
grep -Fx 'compose_project=\"sample-project\" compose_volume=\"data\" compose_version=\"2.0.0\"' /tmp/compose-audit.log
grep -Fx 'id=\"network-id\" name=\"sample-network\" driver=\"bridge\" scope=\"local\" internal=false' /tmp/compose-audit.log
grep -Fx 'compose_project=\"sample-project\" compose_network=\"default\" compose_version=\"2.0.0\"' /tmp/compose-audit.log
! grep -F 'compose_project=\"sample-project' /tmp/compose-audit.log | grep -F 'forged=true' | grep -Fvx 'compose_project=\"sample-project\nforged=true\" compose_service=\"sample-service\" compose_working_dir=\"/srv/sample\" compose_config_files=\"/srv/sample/compose.yml\" compose_oneoff=\"False\" compose_version=\"2.0.0\"'
if grep -E '(^| )(stop|rm|prune|update|restart)( |$)|compose( |.* )down( |$)' /tmp/fake-docker.commands; then
  echo 'mutation docker subcommand used by audit' >&2
  exit 30
fi
expected_rule='Cmnd_Alias VDS_GUARDIAN_AUDIT = /usr/local/sbin/vds-guardianctl audit-compose-projects, /usr/local/sbin/vds-guardianctl audit-root-storage, /usr/local/sbin/vds-guardianctl audit-storage, /usr/local/sbin/vds-guardianctl audit-services, /usr/local/sbin/vds-guardianctl audit-security, /usr/local/sbin/vds-guardianctl verify-health'
test \"\$(grep '^Cmnd_Alias VDS_GUARDIAN_AUDIT = ' /etc/sudoers.d/vds-guardian)\" = \"\$expected_rule\"
touch /tmp/fake-docker.fail
if sudo -u guardian sudo -n /usr/local/sbin/vds-guardianctl audit-compose-projects >/dev/null 2>&1; then
  echo 'audit-compose-projects did not fail closed on inventory error' >&2
  exit 36
fi
rm /tmp/fake-docker.fail
sudo -u guardian sudo -n /usr/local/sbin/vds-guardianctl verify-health >/tmp/verify.log
if sudo -u guardian sudo -n /usr/local/sbin/vds-guardianctl audit-compose-projects extra >/dev/null 2>&1; then
  echo 'audit-compose-projects extra argument unexpectedly accepted' >&2
  exit 35
fi
if sudo -u guardian sudo -n /usr/local/sbin/vds-guardianctl verify-health extra >/dev/null 2>&1; then
  echo 'extra argument unexpectedly accepted' >&2
  exit 31
fi
if sudo -u guardian sudo -n /usr/local/sbin/vds-guardianctl unknown >/dev/null 2>&1; then
  echo 'unknown action unexpectedly accepted' >&2
  exit 32
fi
if sudo -u guardian sudo -n /bin/bash -c id >/dev/null 2>&1; then
  echo 'arbitrary root shell unexpectedly accepted' >&2
  exit 33
fi
for group in sudo adm docker systemd-journal; do
  if id -nG guardian | tr ' ' '\\n' | grep -Fxq \"\$group\"; then
    echo \"forbidden group: \$group\" >&2
    exit 34
  fi
done
printf 'integration_%s_ok\\n' '$mode'
"
}

run_container_test new
run_container_test existing

"${DOCKER_RUN[@]}" -v "$ROOT:/repo:ro" "$IMAGE" bash -lc '
set -Eeuo pipefail
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sudo python3 >/dev/null
adduser --disabled-password --gecos "" guardian >/dev/null

baseline_helper=4a1d6c53954b5b88f5a7c01821377142f1e998dc37ac388a4e74d40729282e08
baseline_sudoers=125a74e6ffa5c50d3fecf8142cc7c5a1de3017e455a1c91f87e6f298c8309020
baseline_v2_helper=7c2fe0ed76f2811b9905f1f975c1e8de526313c9466bfb32fd229a7e696e46ae
baseline_v2_sudoers=3580b0d94eb24be1d5a18cab2e6bc40e83c7ec1c09c8fc552f97c595ab131341
baseline_v3_helper=699c1c32b3397cd43302fe3a1a14ec3360e7f95427df8452f8735e61b182117d
baseline_v3_sudoers=3580b0d94eb24be1d5a18cab2e6bc40e83c7ec1c09c8fc552f97c595ab131341
baseline_v4_helper=42dbb4c4146cbb323fa807a7f35ca6e813d4af03bda027f5f2de9f4c5f1a2169
baseline_v4_sudoers=37a03d5d96f9a149acc42240068bf7ddcc3ec766fb13667f87812e289b3e0d76
baseline_v5_helper=26a83ff99dfd63640b0a14d069fdeb0a8235b1c80fefa4d8168d6d3064084fbc
baseline_v5_sudoers=d656075f924c9d5b047fa75c8072cdf99e399220b4e858fd435a36e492fb8004
baseline_v6_helper=1e01e3f0e10b0a900da09ac5485bf74a4cc9843a47cc2aea921372029d4b5aed
baseline_v6_sudoers=7ce85ca65cd4cb384fd514aaad0d00eb8a1ffc50e2a288f07a33f99f0f14eb94
new_helper=$(sha256sum /repo/src/vds-guardianctl | cut -d" " -f1)
new_sudoers=$(sha256sum /repo/src/vds-guardian.sudoers | cut -d" " -f1)

install_baseline() {
  rm -f /usr/local/sbin/vds-guardianctl /etc/sudoers.d/vds-guardian
  install -o root -g root -m 0755 /repo/tests/fixtures/vds-guardianctl-5a78cb9 /usr/local/sbin/vds-guardianctl
  install -o root -g root -m 0440 /repo/tests/fixtures/vds-guardian.sudoers-5a78cb9 /etc/sudoers.d/vds-guardian
  test "$(sha256sum /usr/local/sbin/vds-guardianctl | cut -d" " -f1)" = "$baseline_helper"
  test "$(sha256sum /etc/sudoers.d/vds-guardian | cut -d" " -f1)" = "$baseline_sudoers"
}

install_baseline_v2() {
  rm -f /usr/local/sbin/vds-guardianctl /etc/sudoers.d/vds-guardian
  install -o root -g root -m 0755 /repo/tests/fixtures/vds-guardianctl-3d20e7d /usr/local/sbin/vds-guardianctl
  install -o root -g root -m 0440 /repo/tests/fixtures/vds-guardian.sudoers-3d20e7d /etc/sudoers.d/vds-guardian
  test "$(sha256sum /usr/local/sbin/vds-guardianctl | cut -d" " -f1)" = "$baseline_v2_helper"
  test "$(sha256sum /etc/sudoers.d/vds-guardian | cut -d" " -f1)" = "$baseline_v2_sudoers"
}

install_baseline_v3() {
  rm -f /usr/local/sbin/vds-guardianctl /etc/sudoers.d/vds-guardian
  install -o root -g root -m 0755 /repo/tests/fixtures/vds-guardianctl-3de0e74 /usr/local/sbin/vds-guardianctl
  install -o root -g root -m 0440 /repo/tests/fixtures/vds-guardian.sudoers-3de0e74 /etc/sudoers.d/vds-guardian
  test "$(sha256sum /usr/local/sbin/vds-guardianctl | cut -d" " -f1)" = "$baseline_v3_helper"
  test "$(sha256sum /etc/sudoers.d/vds-guardian | cut -d" " -f1)" = "$baseline_v3_sudoers"
}

install_baseline_v4() {
  rm -f /usr/local/sbin/vds-guardianctl /etc/sudoers.d/vds-guardian
  install -o root -g root -m 0755 /repo/tests/fixtures/vds-guardianctl-16db836 /usr/local/sbin/vds-guardianctl
  install -o root -g root -m 0440 /repo/tests/fixtures/vds-guardian.sudoers-16db836 /etc/sudoers.d/vds-guardian
  test "$(sha256sum /usr/local/sbin/vds-guardianctl | cut -d" " -f1)" = "$baseline_v4_helper"
  test "$(sha256sum /etc/sudoers.d/vds-guardian | cut -d" " -f1)" = "$baseline_v4_sudoers"
}

install_baseline_v5() {
  rm -f /usr/local/sbin/vds-guardianctl /etc/sudoers.d/vds-guardian
  install -o root -g root -m 0755 /repo/tests/fixtures/vds-guardianctl-304d084 /usr/local/sbin/vds-guardianctl
  install -o root -g root -m 0440 /repo/tests/fixtures/vds-guardian.sudoers-304d084 /etc/sudoers.d/vds-guardian
  test "$(sha256sum /usr/local/sbin/vds-guardianctl | cut -d" " -f1)" = "$baseline_v5_helper"
  test "$(sha256sum /etc/sudoers.d/vds-guardian | cut -d" " -f1)" = "$baseline_v5_sudoers"
}

install_baseline_v6() {
  rm -f /usr/local/sbin/vds-guardianctl /etc/sudoers.d/vds-guardian
  install -o root -g root -m 0755 /repo/tests/fixtures/vds-guardianctl-fc50008 /usr/local/sbin/vds-guardianctl
  install -o root -g root -m 0440 /repo/tests/fixtures/vds-guardian.sudoers-fc50008 /etc/sudoers.d/vds-guardian
  test "$(sha256sum /usr/local/sbin/vds-guardianctl | cut -d" " -f1)" = "$baseline_v6_helper"
  test "$(sha256sum /etc/sudoers.d/vds-guardian | cut -d" " -f1)" = "$baseline_v6_sudoers"
}

install_baseline
install -o root -g root -m 0755 /repo/tests/fake-docker /usr/bin/docker
rm -f /tmp/fake-docker.commands

# A second upgrader fails fast while the known production lock is held and
# cannot mutate either baseline leaf. Hold the lock on this shell descriptor
# so releasing it cannot leave an orphaned child process with the lock open.
exec {test_lock_fd}>/run/vds-guardian-upgrade.lock
flock -n "$test_lock_fd"
if bash /repo/dist/upgrade-existing.sh >/tmp/concurrent.log 2>&1; then
  echo "upgrade ignored the exclusive lock" >&2
  exit 74
fi
grep -Fq "another guardian upgrade is already running" /tmp/concurrent.log || { cat /tmp/concurrent.log >&2; exit 79; }
test "$(sha256sum /usr/local/sbin/vds-guardianctl | cut -d" " -f1)" = "$baseline_helper"
test "$(sha256sum /etc/sudoers.d/vds-guardian | cut -d" " -f1)" = "$baseline_sudoers"
flock -u "$test_lock_fd"
exec {test_lock_fd}>&-

# Unsafe parent metadata and symlink leaves reject before mutation.
chmod 0775 /usr/local/sbin
if bash /repo/dist/upgrade-existing.sh >/tmp/unsafe-parent.log 2>&1; then
  echo "upgrade accepted a group-writable parent" >&2
  exit 75
fi
test "$(sha256sum /usr/local/sbin/vds-guardianctl | cut -d" " -f1)" = "$baseline_helper"
test "$(sha256sum /etc/sudoers.d/vds-guardian | cut -d" " -f1)" = "$baseline_sudoers"
chmod 0755 /usr/local/sbin

root_mode=$(stat -c "%a" /)
chmod 0775 /
if bash /repo/dist/upgrade-existing.sh >/tmp/unsafe-root.log 2>&1; then
  echo "upgrade accepted a group-writable root directory" >&2
  exit 80
fi
test "$(sha256sum /usr/local/sbin/vds-guardianctl | cut -d" " -f1)" = "$baseline_helper"
test "$(sha256sum /etc/sudoers.d/vds-guardian | cut -d" " -f1)" = "$baseline_sudoers"
chmod "$root_mode" /

mv /usr/local/sbin/vds-guardianctl /tmp/baseline-helper
ln -s /tmp/baseline-helper /usr/local/sbin/vds-guardianctl
if bash /repo/dist/upgrade-existing.sh >/tmp/symlink-leaf.log 2>&1; then
  echo "upgrade accepted a symlink helper leaf" >&2
  exit 76
fi
test "$(sha256sum /tmp/baseline-helper | cut -d" " -f1)" = "$baseline_helper"
rm /usr/local/sbin/vds-guardianctl
mv /tmp/baseline-helper /usr/local/sbin/vds-guardianctl

# Numeric group zero is forbidden independently of the named allowlist.
usermod -g 0 guardian
if bash /repo/dist/upgrade-existing.sh >/tmp/root-gid.log 2>&1; then
  echo "upgrade accepted guardian primary gid 0" >&2
  exit 77
fi
test "$(sha256sum /usr/local/sbin/vds-guardianctl | cut -d" " -f1)" = "$baseline_helper"
test "$(sha256sum /etc/sudoers.d/vds-guardian | cut -d" " -f1)" = "$baseline_sudoers"
usermod -g guardian guardian

bash /repo/dist/upgrade-existing.sh >/tmp/upgrade.log
cmp -s /repo/src/vds-guardianctl /usr/local/sbin/vds-guardianctl
cmp -s /repo/src/vds-guardian.sudoers /etc/sudoers.d/vds-guardian
test "$(stat -c "%U:%G %a" /usr/local/sbin/vds-guardianctl)" = "root:root 755"
test "$(stat -c "%U:%G %a" /etc/sudoers.d/vds-guardian)" = "root:root 440"
test ! -e /tmp/fake-docker.commands

# Exact-current reruns are successful and do not mutate the installed files.
bash /repo/dist/upgrade-existing.sh >/tmp/upgrade-idempotent.log
test "$(sha256sum /usr/local/sbin/vds-guardianctl | cut -d" " -f1)" = "$new_helper"
test "$(sha256sum /etc/sudoers.d/vds-guardian | cut -d" " -f1)" = "$new_sudoers"

# The exact current production pair from fc50008 upgrades successfully.
install_baseline_v6
bash /repo/dist/upgrade-existing.sh >/tmp/upgrade-v6.log
test "$(sha256sum /usr/local/sbin/vds-guardianctl | cut -d" " -f1)" = "$new_helper"
test "$(sha256sum /etc/sudoers.d/vds-guardian | cut -d" " -f1)" = "$new_sudoers"

# The exact 304d084 pair upgrades successfully.
install_baseline_v5
bash /repo/dist/upgrade-existing.sh >/tmp/upgrade-v5.log
test "$(sha256sum /usr/local/sbin/vds-guardianctl | cut -d" " -f1)" = "$new_helper"
test "$(sha256sum /etc/sudoers.d/vds-guardian | cut -d" " -f1)" = "$new_sudoers"

# The preceding deployed published pair upgrades successfully.
install_baseline_v4
bash /repo/dist/upgrade-existing.sh >/tmp/upgrade-v4.log
test "$(sha256sum /usr/local/sbin/vds-guardianctl | cut -d" " -f1)" = "$new_helper"
test "$(sha256sum /etc/sudoers.d/vds-guardian | cut -d" " -f1)" = "$new_sudoers"

# The preceding published pair also upgrades successfully.
install_baseline_v3
bash /repo/dist/upgrade-existing.sh >/tmp/upgrade-v3.log
test "$(sha256sum /usr/local/sbin/vds-guardianctl | cut -d" " -f1)" = "$new_helper"
test "$(sha256sum /etc/sudoers.d/vds-guardian | cut -d" " -f1)" = "$new_sudoers"

# The older published pair also upgrades, but supported hashes from different
# releases cannot be mixed into an accepted baseline.
install_baseline_v2
bash /repo/dist/upgrade-existing.sh >/tmp/upgrade-v2.log
test "$(sha256sum /usr/local/sbin/vds-guardianctl | cut -d" " -f1)" = "$new_helper"
test "$(sha256sum /etc/sudoers.d/vds-guardian | cut -d" " -f1)" = "$new_sudoers"
install_baseline_v2
install -o root -g root -m 0440 /repo/tests/fixtures/vds-guardian.sudoers-5a78cb9 /etc/sudoers.d/vds-guardian
if bash /repo/dist/upgrade-existing.sh >/tmp/mixed-baseline.log 2>&1; then
  echo "upgrade accepted a mixed supported baseline pair" >&2
  exit 81
fi
test "$(sha256sum /usr/local/sbin/vds-guardianctl | cut -d" " -f1)" = "$baseline_v2_helper"
test "$(sha256sum /etc/sudoers.d/vds-guardian | cut -d" " -f1)" = "$baseline_sudoers"

install_baseline_v4
install -o root -g root -m 0440 /repo/tests/fixtures/vds-guardian.sudoers-3de0e74 /etc/sudoers.d/vds-guardian
if bash /repo/dist/upgrade-existing.sh >/tmp/mixed-baseline-v4.log 2>&1; then
  echo "upgrade accepted a mixed V4 baseline pair" >&2
  exit 82
fi
test "$(sha256sum /usr/local/sbin/vds-guardianctl | cut -d" " -f1)" = "$baseline_v4_helper"
test "$(sha256sum /etc/sudoers.d/vds-guardian | cut -d" " -f1)" = "$baseline_v3_sudoers"

install_baseline_v5
install -o root -g root -m 0440 /repo/tests/fixtures/vds-guardian.sudoers-16db836 /etc/sudoers.d/vds-guardian
if bash /repo/dist/upgrade-existing.sh >/tmp/mixed-baseline-v5.log 2>&1; then
  echo "upgrade accepted a mixed V5 baseline pair" >&2
  exit 83
fi
test "$(sha256sum /usr/local/sbin/vds-guardianctl | cut -d" " -f1)" = "$baseline_v5_helper"
test "$(sha256sum /etc/sudoers.d/vds-guardian | cut -d" " -f1)" = "$baseline_v4_sudoers"

install_baseline_v6
install -o root -g root -m 0440 /repo/tests/fixtures/vds-guardian.sudoers-304d084 /etc/sudoers.d/vds-guardian
if bash /repo/dist/upgrade-existing.sh >/tmp/mixed-baseline-v6.log 2>&1; then
  echo "upgrade accepted a mixed V6 baseline pair" >&2
  exit 84
fi
test "$(sha256sum /usr/local/sbin/vds-guardianctl | cut -d" " -f1)" = "$baseline_v6_helper"
test "$(sha256sum /etc/sudoers.d/vds-guardian | cut -d" " -f1)" = "$baseline_v5_sudoers"

# Either member drifting from the exact baseline rejects the whole upgrade.
install_baseline
printf "# drift\n" >>/usr/local/sbin/vds-guardianctl
drifted_helper=$(sha256sum /usr/local/sbin/vds-guardianctl | cut -d" " -f1)
if bash /repo/dist/upgrade-existing.sh >/tmp/drift-helper.log 2>&1; then
  echo "upgrade accepted drifted helper" >&2
  exit 71
fi
test "$(sha256sum /usr/local/sbin/vds-guardianctl | cut -d" " -f1)" = "$drifted_helper"
test "$(sha256sum /etc/sudoers.d/vds-guardian | cut -d" " -f1)" = "$baseline_sudoers"

install_baseline
printf "# drift\n" >>/etc/sudoers.d/vds-guardian
drifted_sudoers=$(sha256sum /etc/sudoers.d/vds-guardian | cut -d" " -f1)
if bash /repo/dist/upgrade-existing.sh >/tmp/drift-sudoers.log 2>&1; then
  echo "upgrade accepted drifted sudoers" >&2
  exit 72
fi
test "$(sha256sum /usr/local/sbin/vds-guardianctl | cut -d" " -f1)" = "$baseline_helper"
test "$(sha256sum /etc/sudoers.d/vds-guardian | cut -d" " -f1)" = "$drifted_sudoers"

# Force the post-install visudo check to fail after both files were installed.
# The ERR rollback must restore the exact V6 files, including exact modes.
install_baseline_v6
mv /usr/sbin/visudo /usr/sbin/visudo.real
printf "%s\n" \
  "#!/bin/bash" \
  "count=0" \
  "[[ -f /tmp/visudo-count ]] && read -r count </tmp/visudo-count" \
  "count=\$((count + 1))" \
  "printf \"%s\\n\" \"\$count\" >/tmp/visudo-count" \
  "[[ \$count -ne 2 ]] || exit 99" \
  "exec /usr/sbin/visudo.real \"\$@\"" >/usr/sbin/visudo
chmod 0755 /usr/sbin/visudo
if bash /repo/dist/upgrade-existing.sh >/tmp/late-failure.log 2>&1; then
  echo "upgrade unexpectedly survived artificial late failure" >&2
  exit 73
fi
test "$(sha256sum /usr/local/sbin/vds-guardianctl | cut -d" " -f1)" = "$baseline_v6_helper"
test "$(sha256sum /etc/sudoers.d/vds-guardian | cut -d" " -f1)" = "$baseline_v6_sudoers"
test "$(stat -c "%U:%G %a" /usr/local/sbin/vds-guardianctl)" = "root:root 755"
test "$(stat -c "%U:%G %a" /etc/sudoers.d/vds-guardian)" = "root:root 440"
/usr/sbin/visudo.real -cf /etc/sudoers.d/vds-guardian >/dev/null
test "$(cat /tmp/visudo-count)" = 3
! grep -Fq CRITICAL /tmp/late-failure.log

# If rollback validation itself fails, restoration is still attempted for both
# leaves, the result remains non-zero, and operators receive a machine-greppable
# CRITICAL diagnostic. Calls: embedded=1, post-install=2, rollback=3.
install_baseline_v6
printf "%s\n" \
  "#!/bin/bash" \
  "count=0" \
  "[[ -f /tmp/visudo-count-critical ]] && read -r count </tmp/visudo-count-critical" \
  "count=\$((count + 1))" \
  "printf \"%s\\n\" \"\$count\" >/tmp/visudo-count-critical" \
  "[[ \$count -lt 2 ]] || exit 98" \
  "exec /usr/sbin/visudo.real \"\$@\"" >/usr/sbin/visudo
chmod 0755 /usr/sbin/visudo
if bash /repo/dist/upgrade-existing.sh >/tmp/rollback-validation-failure.log 2>&1; then
  echo "upgrade masked rollback validation failure" >&2
  exit 78
fi
grep -Fq "CRITICAL: restored sudoers failed metadata, hash, or visudo verification" /tmp/rollback-validation-failure.log
test "$(sha256sum /usr/local/sbin/vds-guardianctl | cut -d" " -f1)" = "$baseline_v6_helper"
test "$(sha256sum /etc/sudoers.d/vds-guardian | cut -d" " -f1)" = "$baseline_v6_sudoers"
test "$(stat -c "%U:%G %a" /usr/local/sbin/vds-guardianctl)" = "root:root 755"
test "$(stat -c "%U:%G %a" /etc/sudoers.d/vds-guardian)" = "root:root 440"
printf "%s\n" "upgrade_existing_lock_boundaries_identity_and_verified_rollback_ok"
'

"${DOCKER_RUN[@]}" -v "$ROOT:/repo:ro" "$IMAGE" bash -lc '
set -Eeuo pipefail
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sudo python3 openssh-client >/dev/null
adduser --disabled-password --gecos "" guardian >/dev/null
groupadd disk-test
usermod -aG disk-test guardian
if bash /repo/dist/install-existing.sh >/tmp/unexpected.log 2>&1; then
  echo "existing installer accepted an unexpected group" >&2
  exit 41
fi
test ! -e /usr/local/sbin/vds-guardianctl
test ! -e /etc/sudoers.d/vds-guardian
printf "%s\n" "unexpected_existing_group_rejected"
'

"${DOCKER_RUN[@]}" -v "$ROOT:/repo:ro" "$IMAGE" bash -lc '
set -Eeuo pipefail
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sudo python3 openssh-client >/dev/null
groupadd docker
printf "%s\n" "ADD_EXTRA_GROUPS=1" "EXTRA_GROUPS=\"docker\"" >>/etc/adduser.conf
ssh-keygen -q -t ed25519 -N "" -f /tmp/test_guardian_key
public_key=$(cat /tmp/test_guardian_key.pub)
enrollment_token='vg1_0123456789abcdefghijklmnopqrstuvwxyz_A-BCDE'
printf "%s\n" "$enrollment_token" >/tmp/enrollment-token
chmod 600 /tmp/enrollment-token
if bash /repo/dist/install-new.sh --public-key "$public_key" --enrollment-token-file /tmp/enrollment-token >/tmp/unexpected.log 2>&1; then
  echo "new installer accepted an unexpected adduser group" >&2
  exit 42
fi
if getent passwd guardian >/dev/null; then
  echo "new installer did not remove rejected account" >&2
  exit 43
fi
test ! -e /usr/local/sbin/vds-guardianctl
test ! -e /etc/sudoers.d/vds-guardian
printf "%s\n" "unexpected_new_group_rejected_and_rolled_back"
'

"${DOCKER_RUN[@]}" -v "$ROOT:/repo:ro" "$IMAGE" bash -lc '
set -Eeuo pipefail
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sudo python3 openssh-client >/dev/null
ssh-keygen -q -t ed25519 -N "" -f /tmp/test_guardian_key
public_key=$(cat /tmp/test_guardian_key.pub)
if bash /repo/dist/install-new.sh --public-key "$public_key" >/tmp/missing-token.log 2>&1; then
  echo "new installer accepted a missing enrollment token" >&2
  exit 51
fi
printf "%s\n" "vg1_too-short" >/tmp/enrollment-token
chmod 600 /tmp/enrollment-token
if bash /repo/dist/install-new.sh --public-key "$public_key" --enrollment-token-file /tmp/enrollment-token >/tmp/invalid-token.log 2>&1; then
  echo "new installer accepted an invalid enrollment token" >&2
  exit 52
fi
invalid_index=0
for invalid_token in \
  "vg1_0123456789abcdefghijklmnopqrstuvwxyz_A-BCD" \
  "vg1_0123456789abcdefghijklmnopqrstuvwxyz_A-BCDEF" \
  "bad_0123456789abcdefghijklmnopqrstuvwxyz_A-BCDE" \
  "vg1_0123456789abcdefghijklmnopqrstuvwxyz_A=BCDE"; do
  invalid_index=$((invalid_index + 1))
  printf "%s\n" "$invalid_token" >/tmp/enrollment-token
  chmod 600 /tmp/enrollment-token
  if bash /repo/dist/install-new.sh --public-key "$public_key" --enrollment-token-file /tmp/enrollment-token >/tmp/invalid-token.log 2>&1; then
    echo "new installer accepted invalid enrollment token case $invalid_index length ${#invalid_token}" >&2
    exit 53
  fi
  ! grep -F "$invalid_token" /tmp/invalid-token.log
done
valid_token="vg1_0123456789abcdefghijklmnopqrstuvwxyz_A-BCDE"
printf "%s\n" "$valid_token" >/tmp/enrollment-token
chmod 600 /tmp/enrollment-token
if bash /repo/dist/install-new.sh --enrollment-token-file /tmp/enrollment-token --public-key "$public_key" >/tmp/wrong-order.log 2>&1; then
  echo "new installer accepted reordered arguments" >&2
  exit 54
fi
if bash /repo/dist/install-new.sh --public-key "$public_key" --enrollment-token-file /tmp/enrollment-token extra >/tmp/extra-argument.log 2>&1; then
  echo "new installer accepted an extra argument" >&2
  exit 55
fi
test ! -e /home/guardian
test ! -e /usr/local/sbin/vds-guardianctl
test ! -e /etc/sudoers.d/vds-guardian
printf "%s\n" "invalid_enrollment_tokens_rejected"
'

"${DOCKER_RUN[@]}" -v "$ROOT:/repo:ro" "$IMAGE" bash -lc '
set -Eeuo pipefail
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sudo python3 openssh-client >/dev/null
ssh-keygen -q -t ed25519 -N "" -f /tmp/test_guardian_key
public_key=$(cat /tmp/test_guardian_key.pub)
enrollment_token="vg1_0123456789abcdefghijklmnopqrstuvwxyz_A-BCDE"
printf "%s\n" "$enrollment_token" >/tmp/enrollment-token
chmod 600 /tmp/enrollment-token
rm -rf /etc/sudoers.d
if bash /repo/dist/install-new.sh --public-key "$public_key" --enrollment-token-file /tmp/enrollment-token >/tmp/rollback.log 2>&1; then
  echo "new installer unexpectedly succeeded without /etc/sudoers.d" >&2
  exit 61
fi
! grep -F "$enrollment_token" /tmp/rollback.log
! getent passwd guardian >/dev/null
test ! -e /home/guardian
test ! -e /usr/local/sbin/vds-guardianctl
test ! -e /etc/sudoers.d/vds-guardian
printf "%s\n" "failed_install_rolled_back"
'

"${DOCKER_RUN[@]}" -v "$ROOT:/repo:ro" "$IMAGE" bash -lc '
set -Eeuo pipefail
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sudo python3 openssh-client >/dev/null
ssh-keygen -q -t ed25519 -N "" -f /tmp/test_guardian_key
public_key=$(cat /tmp/test_guardian_key.pub)
enrollment_token="vg1_0123456789abcdefghijklmnopqrstuvwxyz_A-BCDE"
printf "%s\n" "$enrollment_token" >/tmp/enrollment-token
chmod 600 /tmp/enrollment-token
mv /usr/sbin/adduser /usr/sbin/adduser.real
printf "%s\n" "#!/bin/bash" "sleep 2" "exec /usr/sbin/adduser.real \"\$@\"" >/usr/sbin/adduser
chmod 755 /usr/sbin/adduser
bash /repo/dist/install-new.sh --public-key "$public_key" --enrollment-token-file /tmp/enrollment-token >/tmp/install.log 2>&1 &
installer_pid=$!
sleep 0.2
if tr "\000" "\n" </proc/$installer_pid/cmdline | grep -F "$enrollment_token"; then
  echo "enrollment token leaked through installer argv" >&2
  exit 81
fi
if tr "\000" "\n" </proc/$installer_pid/environ | grep -F "$enrollment_token"; then
  echo "enrollment token leaked through installer environment" >&2
  exit 82
fi
wait "$installer_pid"
! grep -F "$enrollment_token" /tmp/install.log
printf "%s\n" "installer_process_token_not_exposed"
'
