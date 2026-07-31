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
  bash /repo/dist/install-new.sh --public-key \"\$public_key\" --enrollment-token \"\$enrollment_token\" >/tmp/install.log
  ! grep -F \"\$enrollment_token\" /tmp/install.log
  test \"\$(cat /home/guardian/.vds-guardian-enrollment)\" = \"\$enrollment_token\"
  test \"\$(stat -c '%U:%G %a' /home/guardian/.vds-guardian-enrollment)\" = 'guardian:guardian 600'
else
  adduser --disabled-password --gecos '' guardian >/dev/null
  bash /repo/dist/install-existing.sh >/tmp/install.log
fi
id guardian
stat -c '%U:%G %a %n' /usr/local/sbin/vds-guardianctl /etc/sudoers.d/vds-guardian
sudo -u guardian sudo -n /usr/local/sbin/vds-guardianctl verify-health >/tmp/verify.log
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
if bash /repo/dist/install-new.sh --public-key "$public_key" --enrollment-token "$enrollment_token" >/tmp/unexpected.log 2>&1; then
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
if bash /repo/dist/install-new.sh --public-key "$public_key" --enrollment-token "vg1_too-short" >/tmp/invalid-token.log 2>&1; then
  echo "new installer accepted an invalid enrollment token" >&2
  exit 52
fi
for invalid_token in \
  "vg1_0123456789abcdefghijklmnopqrstuvwxyz_A-BCD" \
  "vg1_0123456789abcdefghijklmnopqrstuvwxyz_A-BCDEF" \
  "bad_0123456789abcdefghijklmnopqrstuvwxyz_A-BCDE" \
  "vg1_0123456789abcdefghijklmnopqrstuvwxyz_A=BCDE"; do
  if bash /repo/dist/install-new.sh --public-key "$public_key" --enrollment-token "$invalid_token" >/tmp/invalid-token.log 2>&1; then
    echo "new installer accepted an invalid enrollment token" >&2
    exit 53
  fi
  ! grep -F "$invalid_token" /tmp/invalid-token.log
done
valid_token="vg1_0123456789abcdefghijklmnopqrstuvwxyz_A-BCDE"
if bash /repo/dist/install-new.sh --enrollment-token "$valid_token" --public-key "$public_key" >/tmp/wrong-order.log 2>&1; then
  echo "new installer accepted reordered arguments" >&2
  exit 54
fi
if bash /repo/dist/install-new.sh --public-key "$public_key" --enrollment-token "$valid_token" extra >/tmp/extra-argument.log 2>&1; then
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
rm -rf /etc/sudoers.d
if bash /repo/dist/install-new.sh --public-key "$public_key" --enrollment-token "$enrollment_token" >/tmp/rollback.log 2>&1; then
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
