#!/bin/bash
set -Eeuo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
IMAGE=${VDS_GUARDIAN_TEST_IMAGE:-debian:12-slim}

python3 "$ROOT/tools/build.py"
bash -n "$ROOT/src/vds-guardianctl"
bash -n "$ROOT/dist/install-new.sh"
bash -n "$ROOT/dist/install-existing.sh"
visudo -cf "$ROOT/src/vds-guardian.sudoers"
(cd "$ROOT" && sha256sum -c SHA256SUMS)

# Inspection templates must select only reviewed metadata and must never dump
# environment, label maps, config/secret contents, or volume mountpoints.
if grep -En '\{\{[[:space:]]*(json[[:space:]]+)?\.Config\.Env|\{\{[[:space:]]*(json[[:space:]]+)?\.Config\.Labels[[:space:]]*\}\}|\{\{[[:space:]]*(json[[:space:]]+)?\.Labels[[:space:]]*\}\}|\.Configs|\.Secrets|\.Mountpoint' \
  "$ROOT/src/vds-guardianctl" "$ROOT/dist/install-new.sh" "$ROOT/dist/install-existing.sh"; then
  echo 'sensitive Docker inspection template found' >&2
  exit 20
fi
grep -Fq 'compose_project={{printf "%q" (index .Labels "com.docker.compose.project")}} compose_volume={{printf "%q" (index .Labels "com.docker.compose.volume")}} compose_version={{printf "%q" (index .Labels "com.docker.compose.version")}}' "$ROOT/src/vds-guardianctl"
grep -Fq 'compose_project={{printf "%q" (index .Labels "com.docker.compose.project")}} compose_network={{printf "%q" (index .Labels "com.docker.compose.network")}} compose_version={{printf "%q" (index .Labels "com.docker.compose.version")}}' "$ROOT/src/vds-guardianctl"
grep -Fq 'name={{printf "%q" .Name}} source={{printf "%q" .Source}}' "$ROOT/src/vds-guardianctl"

run_container_test() {
  local mode=$1
  docker run --rm -v "$ROOT:/repo:ro" "$IMAGE" bash -lc "
set -Eeuo pipefail
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sudo openssh-client iproute2 >/dev/null
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
install -o root -g root -m 0755 /repo/tests/fake-docker /usr/bin/docker
rm -f /tmp/fake-docker.commands
sudo -u guardian sudo -n /usr/local/sbin/vds-guardianctl audit-compose-projects >/tmp/compose-audit.log
grep -Fx 'id=\"container-id\" name=\"sample-container\" image=\"sample-image\" state=\"running\" status=\"Up 1 minute\"' /tmp/compose-audit.log
grep -Fx 'id=\"container-id\" name=\"/sample-container\" image=\"sample-image\" state=\"running\" restart_policy=\"unless-stopped\"' /tmp/compose-audit.log
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
expected_rule='Cmnd_Alias VDS_GUARDIAN_AUDIT = /usr/local/sbin/vds-guardianctl audit-compose-projects, /usr/local/sbin/vds-guardianctl audit-storage, /usr/local/sbin/vds-guardianctl audit-services, /usr/local/sbin/vds-guardianctl audit-security, /usr/local/sbin/vds-guardianctl verify-health'
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

docker run --rm -v "$ROOT:/repo:ro" "$IMAGE" bash -lc '
set -Eeuo pipefail
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sudo openssh-client >/dev/null
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

docker run --rm -v "$ROOT:/repo:ro" "$IMAGE" bash -lc '
set -Eeuo pipefail
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sudo openssh-client >/dev/null
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

docker run --rm -v "$ROOT:/repo:ro" "$IMAGE" bash -lc '
set -Eeuo pipefail
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sudo openssh-client >/dev/null
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

docker run --rm -v "$ROOT:/repo:ro" "$IMAGE" bash -lc '
set -Eeuo pipefail
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sudo openssh-client >/dev/null
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

docker run --rm -v "$ROOT:/repo:ro" "$IMAGE" bash -lc '
set -Eeuo pipefail
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sudo openssh-client >/dev/null
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
