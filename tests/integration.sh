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
  bash /repo/dist/install-new.sh --public-key \"\$public_key\" >/tmp/install.log
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
if bash /repo/dist/install-new.sh --public-key "$public_key" >/tmp/unexpected.log 2>&1; then
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
