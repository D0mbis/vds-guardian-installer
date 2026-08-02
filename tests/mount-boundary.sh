#!/bin/bash
set -Eeuo pipefail

apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 util-linux >/dev/null
install -o root -g root -m 0755 /repo/src/vds-guardianctl /usr/local/sbin/vds-guardianctl
install -o root -g root -m 0755 /repo/tests/stateful-fake-docker /usr/bin/docker
install -d -o root -g root -m 0755 /etc/vds-guardian/manifests '/root/config tree/nested mount' '/root/protected source'
printf 'must-survive\n' >'/root/protected source/sentinel'

if ! mount --bind '/root/protected source' '/root/config tree/nested mount'; then
  printf '%s\n' 'SKIP nested_bind_mount_boundary: test container lacks CAP_SYS_ADMIN or permits no mounts'
  exit 0
fi
cleanup() { umount '/root/config tree/nested mount' 2>/dev/null || true; }
trap cleanup EXIT

a=$(stat -c %d '/root/protected source')
b=$(stat -c %d '/root/config tree/nested mount')
test "$a" = "$b"
A=$(printf a%.0s {1..64}); N=$(printf d%.0s {1..64}); P=$(printf e%.0s {1..64}); I=$(printf f%.0s {1..64})
python3 - "$A" "$N" "$P" "$I" <<'PY'
import json,sys
A,N,P,I=sys.argv[1:]
mounts=[{"type":"volume","name":"app-data","source":"/var/lib/docker/volumes/app-data/_data","destination":"/data","rw":True},{"type":"bind","name":"","source":"/root/config tree","destination":"/app/config","rw":False}]
c={"id":A,"name":"app-one","project":"app","service":"one","policy":"unless-stopped","state":"running","image":I,"mounts":mounts,"networks":[{"id":P,"name":"shared-net"}]}
s={"containers":[c],"volumes":{"app-data":{"driver":"local","scope":"local","project":"","compose_volume":""}},"networks":{"orphan":{"id":N,"name":"app-orphan","driver":"bridge","scope":"local","internal":False,"project":"app","compose_network":"orphan"},"protected":{"id":P,"name":"shared-net","driver":"bridge","scope":"local","internal":False,"project":"","compose_network":""}},"images":[I],"mutation_count":0}
json.dump(s,open('/tmp/mutation-state.json','w'))
def net(i,n,p,cn):return {"id":i,"name":n,"driver":"bridge","scope":"local","internal":False,"project":p,"compose_network":cn}
cm={"id":A,"name":"app-one","project":"app","service":"one","restart_policy":"unless-stopped","mounts":mounts,"networks":[{"id":P,"name":"shared-net"}]}
m={"schema":1,"action":"purge-approved-compose-project","containers":[cm],"image_ids":[I],"volumes":[{"name":"app-data","driver":"local","scope":"local","project":"","compose_volume":""}],"orphan_network":net(N,"app-orphan","app","orphan"),"protected_networks":[net(P,"shared-net","","")],"config_directory":"/root/config tree"}
json.dump(m,open('/etc/vds-guardian/manifests/purge.json','w'))
PY
chmod 0400 /etc/vds-guardian/manifests/purge.json
rm -f /tmp/mutation-docker.log /run/vds-guardian-mutate.lock
if /usr/local/sbin/vds-guardianctl purge-approved-compose-project >/tmp/reject 2>&1; then
  echo 'purge crossed a same-filesystem nested bind mount' >&2
  exit 1
fi
grep -Fq 'config directory contains a mount boundary' /tmp/reject
! grep -Eq '^(update|stop|rm|volume rm|network rm|image rm)' /tmp/mutation-docker.log
test "$(cat '/root/protected source/sentinel')" = must-survive
mountpoint -q '/root/config tree/nested mount'
printf '%s\n' 'nested_same_filesystem_bind_mount_rejected_zero_mutation'
