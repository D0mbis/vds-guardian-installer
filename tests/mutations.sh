#!/bin/bash
set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
IMAGE=${VDS_GUARDIAN_TEST_IMAGE:-debian:12-slim}
docker run --rm -v "$ROOT:/repo:ro" "$IMAGE" bash -lc '
set -Eeuo pipefail
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sudo python3 >/dev/null
adduser --disabled-password --gecos "" guardian >/dev/null
install -o root -g root -m 0755 /repo/src/vds-guardianctl /usr/local/sbin/vds-guardianctl
install -o root -g root -m 0440 /repo/src/vds-guardian.sudoers /etc/sudoers.d/vds-guardian
install -o root -g root -m 0755 /repo/tests/stateful-fake-docker /usr/bin/docker
install -d -o root -g root -m 0755 /etc/vds-guardian /etc/vds-guardian/manifests
A=$(printf a%.0s {1..64}); B=$(printf b%.0s {1..64}); C=$(printf c%.0s {1..64}); N=$(printf d%.0s {1..64}); P=$(printf e%.0s {1..64}); I=$(printf f%.0s {1..64}); J=$(printf 1%.0s {1..64})
write_state() {
 python3 - "$A" "$B" "$C" "$N" "$P" "$I" <<"PY"
import json,sys
A,B,C,N,P,I=sys.argv[1:]
mounts=[{"type":"volume","name":"app-data","source":"/var/lib/docker/volumes/app-data/_data","destination":"/data","rw":True},{"type":"bind","name":"","source":"/root/textbee","destination":"/app/config","rw":False}]
def c(i,n,service):return {"id":i,"name":n,"project":"app","service":service,"policy":"unless-stopped","auto_remove":False,"state":"running","image":I,"mounts":mounts,"networks":[{"id":P,"name":"shared-net"}]}
s={"containers":[c(A,"app-one","one"),c(B,"app-two","two")],"volumes":{"app-data":{"driver":"local","scope":"local","project":"","compose_volume":""}},"networks":{"orphan":{"id":N,"name":"app-orphan","driver":"bridge","scope":"local","internal":False,"project":"app","compose_network":"orphan"},"protected":{"id":P,"name":"shared-net","driver":"bridge","scope":"local","internal":False,"project":"","compose_network":""}},"images":[I],"mutation_count":0}
json.dump(s,open("/tmp/mutation-state.json","w"))
PY
 rm -f /tmp/mutation-docker.log /run/vds-guardian-mutate.lock
 rm -rf /root/textbee; install -d -o root -g root -m 0755 /root/textbee/nested/deep; printf x >/root/textbee/file; printf y >/root/textbee/nested/deep/file
}
write_purge() {
 python3 - "$A" "$B" "$N" "$P" <<"PY"
import json,sys
A,B,N,P=sys.argv[1:]
mounts=[{"type":"volume","name":"app-data","source":"/var/lib/docker/volumes/app-data/_data","destination":"/data","rw":True},{"type":"bind","name":"","source":"/root/textbee","destination":"/app/config","rw":False}]
def c(i,n,s):return {"id":i,"name":n,"project":"app","service":s,"restart_policy":"unless-stopped","mounts":mounts,"networks":[{"id":P,"name":"shared-net"}]}
def net(i,n,p,cn):return {"id":i,"name":n,"driver":"bridge","scope":"local","internal":False,"project":p,"compose_network":cn}
o={"schema":1,"action":"purge-approved-compose-project","containers":[c(A,"app-one","one"),c(B,"app-two","two")],"image_ids":["f"*64],"volumes":[{"name":"app-data","driver":"local","scope":"local","project":"","compose_volume":""}],"orphan_network":net(N,"app-orphan","app","orphan"),"protected_networks":[net(P,"shared-net","","" )],"config_directory":"/root/textbee"}
json.dump(o,open("/etc/vds-guardian/manifests/purge.json","w"))
PY
 chmod 0400 /etc/vds-guardian/manifests/purge.json
}
write_quiesce() {
 python3 - "$A" "$B" <<"PY"
import json,sys
A,B=sys.argv[1:]
o={"schema":1,"action":"quiesce-approved-compose-project","containers":[{"id":A,"name":"app-one","project":"app","service":"one","restart_policy":"unless-stopped"},{"id":B,"name":"app-two","project":"app","service":"two","restart_policy":"unless-stopped"}]}
json.dump(o,open("/etc/vds-guardian/manifests/quiesce.json","w"))
PY
 chmod 0400 /etc/vds-guardian/manifests/quiesce.json
}
write_remove_state() {
 write_state
 python3 - "$C" "$P" "$I" "$J" <<"PY"
import json,sys
C,P,I,J=sys.argv[1:];p="/tmp/mutation-state.json";s=json.load(open(p));anon="2"*64
s["volumes"][anon]={"driver":"local","scope":"local","project":"","compose_volume":""}
s["containers"].append({"id":C,"name":"other-stopped","project":"other","service":"worker","policy":"always","auto_remove":False,"state":"exited","image":J,"mounts":[{"type":"volume","name":anon,"source":"/var/lib/docker/volumes/"+anon+"/_data","destination":"/state","rw":True},{"type":"bind","name":"","source":"/srv/other","destination":"/config","rw":True}],"networks":[{"id":P,"name":"shared-net"}]})
s["images"].append(J);json.dump(s,open(p,"w"))
PY
 install -d -o root -g root -m 0755 /srv/other; printf preserve >/srv/other/data
}
write_remove() {
 install -d -o guardian -g guardian -m 0700 /home/guardian/.vds-guardian
 python3 - "$A" "$C" "$P" "$I" "$J" <<"PY"
import json,sys
A,C,P,I,J=sys.argv[1:];state=json.load(open("/tmp/mutation-state.json"));wanted={A,C};cs=[]
for x in state["containers"]:
 if x["id"] in wanted:cs.append({"id":x["id"],"name":x["name"],"project":x["project"],"service":x["service"],"image_id":x["image"],"restart_policy":x["policy"],"auto_remove":x.get("auto_remove",False),"mounts":x["mounts"],"networks":x["networks"]})
volumes=[]
for name in {m["name"] for c in cs for m in c["mounts"] if m["type"]=="volume"}:
 v=state["volumes"][name];volumes.append({"name":name,**v})
n=state["networks"]["protected"];networks=[{k:n[k] for k in ["id","name","driver","scope","internal","project","compose_network"]}]
o={"schema":1,"action":"remove-containers-preserve-data","containers":cs,"volumes":volumes,"networks":networks}
json.dump(o,open("/home/guardian/.vds-guardian/remove-containers.json","w"))
PY
 chown guardian:guardian /home/guardian/.vds-guardian/remove-containers.json; chmod 0600 /home/guardian/.vds-guardian/remove-containers.json
}
mutations() { local n; n=$(grep -Ec "^(update|stop|rm|volume rm|network rm|image rm)" /tmp/mutation-docker.log 2>/dev/null || true); printf "%s\\n" "${n:-0}"; }
# Strict malformed input refuses before even contacting Docker.
write_state; printf "{\"schema\":1,\"schema\":1}" >/etc/vds-guardian/manifests/quiesce.json; chmod 0400 /etc/vds-guardian/manifests/quiesce.json
! /usr/local/sbin/vds-guardianctl quiesce-approved-compose-project >/tmp/reject 2>&1
test "$(mutations)" = 0
# Missing and unsafe manifest metadata also refuse before Docker or mutation.
write_state; rm -f /etc/vds-guardian/manifests/quiesce.json
! /usr/local/sbin/vds-guardianctl quiesce-approved-compose-project >/tmp/reject 2>&1
test "$(mutations)" = 0
write_state; write_quiesce; chmod 0600 /etc/vds-guardian/manifests/quiesce.json
! /usr/local/sbin/vds-guardianctl quiesce-approved-compose-project >/tmp/reject 2>&1
test "$(mutations)" = 0
# Quiesce identity drift and an extra project container are zero-mutation failures.
write_state; write_quiesce
python3 - <<"PY"
import json
p="/tmp/mutation-state.json";s=json.load(open(p));s["containers"][0]["service"]="drift";json.dump(s,open(p,"w"))
PY
! /usr/local/sbin/vds-guardianctl quiesce-approved-compose-project >/tmp/reject 2>&1
test "$(mutations)" = 0
write_state; write_quiesce
python3 - "$C" "$I" <<"PY"
import json,sys
C,I=sys.argv[1:];p="/tmp/mutation-state.json";s=json.load(open(p));x=dict(s["containers"][0]);x.update(id=C,name="app-extra",service="extra",mounts=[],networks=[]);s["containers"].append(x);json.dump(s,open(p,"w"))
PY
! /usr/local/sbin/vds-guardianctl quiesce-approved-compose-project >/tmp/reject 2>&1
test "$(mutations)" = 0
# Successful quiesce is ordered, non-destructive, idempotent, and exact sudo rejects arguments.
write_state; write_quiesce
python3 - <<"PY"
import json
p="/tmp/mutation-state.json";s=json.load(open(p));s["containers"][0]["state"]="restarting";json.dump(s,open(p,"w"))
PY
sudo -u guardian sudo -n /usr/local/sbin/vds-guardianctl quiesce-approved-compose-project
! sudo -u guardian sudo -n /usr/local/sbin/vds-guardianctl quiesce-approved-compose-project extra >/dev/null 2>&1
python3 - <<"PY"
import json
s=json.load(open("/tmp/mutation-state.json"));assert len(s["containers"])==2 and all(x["policy"]=="no" and x["state"]=="exited" for x in s["containers"]);assert s["volumes"] and len(s["networks"])==2 and s["images"]
PY
/usr/local/sbin/vds-guardianctl quiesce-approved-compose-project
! grep -Eq "^(rm|volume rm|network rm|image rm)" /tmp/mutation-docker.log
# Lock contention refuses with no mutation.
write_state; write_quiesce
exec {lfd}>/run/vds-guardian-mutate.lock; chmod 600 /run/vds-guardian-mutate.lock; flock -n "$lfd"
! /usr/local/sbin/vds-guardianctl quiesce-approved-compose-project >/tmp/lock 2>&1
grep -Fq "another guardian mutation" /tmp/lock; test "$(mutations)" = 0
flock -u "$lfd"; exec {lfd}>&-
# Guardian-owned removal requests are strict and fail before mutation on unsafe
# metadata, malformed/unknown keys, topology drift, replacements, or Docker errors.
write_remove_state; write_remove; chmod 0644 /home/guardian/.vds-guardian/remove-containers.json
! /usr/local/sbin/vds-guardianctl remove-containers-preserve-data >/tmp/reject 2>&1; test "$(mutations)" = 0
write_remove_state; write_remove; chmod 0755 /home/guardian/.vds-guardian
! /usr/local/sbin/vds-guardianctl remove-containers-preserve-data >/tmp/reject 2>&1; test "$(mutations)" = 0
# A running --rm target with an anonymous volume is rejected by its exact
# requested AutoRemove identity before update or stop. The fake models Docker
# deleting the container and anonymous volume on stop, so both must remain with
# zero mutation.
write_remove_state
python3 - "$A" <<"PY"
import json,sys
A=sys.argv[1];p="/tmp/mutation-state.json";s=json.load(open(p));anon="4"*64;c=next(x for x in s["containers"] if x["id"]==A);c["auto_remove"]=True;c["mounts"][0]={"type":"volume","name":anon,"source":"/var/lib/docker/volumes/"+anon+"/_data","destination":"/data","rw":True};s["volumes"][anon]={"driver":"local","scope":"local","project":"","compose_volume":""};json.dump(s,open(p,"w"))
PY
write_remove
! /usr/local/sbin/vds-guardianctl remove-containers-preserve-data >/tmp/reject 2>&1
grep -Fq "auto-remove containers cannot be safely stopped while preserving data" /tmp/reject
test "$(mutations)" = 0
python3 - "$A" <<"PY"
import json,sys
A=sys.argv[1];s=json.load(open("/tmp/mutation-state.json"));c=next(x for x in s["containers"] if x["id"]==A);assert c["state"]=="running" and c["auto_remove"] is True and "4"*64 in s["volumes"]
PY
write_remove_state; write_remove
python3 - <<"PY"
p="/home/guardian/.vds-guardian/remove-containers.json";b=open(p).read();open(p,"w").write(b.replace("\"schema\": 1","\"schema\": 1, \"schema\": 1",1))
PY
chown guardian:guardian /home/guardian/.vds-guardian/remove-containers.json; chmod 0600 /home/guardian/.vds-guardian/remove-containers.json
! /usr/local/sbin/vds-guardianctl remove-containers-preserve-data >/tmp/reject 2>&1; test "$(mutations)" = 0
write_remove_state; write_remove
python3 - <<"PY"
p="/home/guardian/.vds-guardian/remove-containers.json";b=open(p).read();open(p,"w").write(b[:-1]+",\"unknown\":1}")
PY
chown guardian:guardian /home/guardian/.vds-guardian/remove-containers.json; chmod 0600 /home/guardian/.vds-guardian/remove-containers.json
! /usr/local/sbin/vds-guardianctl remove-containers-preserve-data >/tmp/reject 2>&1; test "$(mutations)" = 0
write_remove_state; write_remove
python3 - <<"PY"
import json
p="/tmp/mutation-state.json";s=json.load(open(p));s["containers"][0]["mounts"][0]["destination"]="/drift";json.dump(s,open(p,"w"))
PY
! /usr/local/sbin/vds-guardianctl remove-containers-preserve-data >/tmp/reject 2>&1; test "$(mutations)" = 0
write_remove_state; write_remove
python3 - "$A" <<"PY"
import json,sys
A=sys.argv[1];p="/tmp/mutation-state.json";s=json.load(open(p));s["containers"][0]["id"]="3"*64;json.dump(s,open(p,"w"))
PY
! /usr/local/sbin/vds-guardianctl remove-containers-preserve-data >/tmp/reject 2>&1; test "$(mutations)" = 0
write_remove_state; write_remove
python3 - <<"PY"
import json
p="/tmp/mutation-state.json";s=json.load(open(p));s["inspect_error"]="network";json.dump(s,open(p,"w"))
PY
! /usr/local/sbin/vds-guardianctl remove-containers-preserve-data >/tmp/reject 2>&1; test "$(mutations)" = 0
# A Docker failure after mutations remains visible, does not trigger forbidden
# cleanup, and leaves every data object present for an explicit retry.
write_remove_state; write_remove
python3 - <<"PY"
import json
p="/tmp/mutation-state.json";s=json.load(open(p));s["fail_mutation"]=4;json.dump(s,open(p,"w"))
PY
! /usr/local/sbin/vds-guardianctl remove-containers-preserve-data >/tmp/remove-partial 2>&1
python3 - <<"PY"
import json
s=json.load(open("/tmp/mutation-state.json"));assert len(s["containers"])==3 and len(s["volumes"])==2 and len(s["networks"])==2 and len(s["images"])==2
PY
! grep -Eq "^(volume rm|network rm|image rm)" /tmp/mutation-docker.log
# Running and stopped targets from different projects are removed by full ID;
# an unrequested container in the same project and all data identities survive.
write_remove_state; write_remove
sudo -u guardian sudo -n /usr/local/sbin/vds-guardianctl remove-containers-preserve-data
! sudo -u guardian sudo -n /usr/local/sbin/vds-guardianctl remove-containers-preserve-data extra >/dev/null 2>&1
python3 - "$B" "$P" "$I" "$J" <<"PY"
import json,sys,os
B,P,I,J=sys.argv[1:];s=json.load(open("/tmp/mutation-state.json"));assert [x["id"] for x in s["containers"]]==[B];assert set(s["volumes"])=={"app-data","2"*64};assert s["networks"]["protected"]["id"]==P and set(s["images"])=={I,J};assert open("/srv/other/data").read()=="preserve" and os.path.exists("/root/textbee/file")
PY
! grep -Eq "^(volume rm|network rm|image rm)" /tmp/mutation-docker.log
grep -Fxq "rm $A" /tmp/mutation-docker.log; grep -Fxq "rm $C" /tmp/mutation-docker.log
# A generic inspect failure is never interpreted as intended absence.
write_state; write_purge
python3 - <<"PY"
import json
p="/tmp/mutation-state.json";s=json.load(open(p));s["inspect_error"]="volume";json.dump(s,open(p,"w"))
PY
! /usr/local/sbin/vds-guardianctl purge-approved-compose-project >/tmp/reject 2>&1
test "$(mutations)" = 0
# Shared volume, orphan endpoint, and unsafe directory each fail preflight with zero mutation.
write_state; write_purge
python3 - <<"PY"
import json
p="/tmp/mutation-state.json";s=json.load(open(p));s["volumes"]["idle-data"]={"driver":"local","scope":"local","project":"","compose_volume":""};json.dump(s,open(p,"w"))
p="/etc/vds-guardian/manifests/purge.json";m=json.load(open(p));m["volumes"].append({"name":"idle-data","driver":"local","scope":"local","project":"","compose_volume":""});json.dump(m,open(p,"w"))
PY
chmod 0400 /etc/vds-guardian/manifests/purge.json
! /usr/local/sbin/vds-guardianctl purge-approved-compose-project >/tmp/reject 2>&1; grep -Fq "declared volumes do not exactly match container mounts" /tmp/reject; test "$(mutations)" = 0
write_state; write_purge
python3 - "$C" "$I" <<"PY"
import json,sys
C,I=sys.argv[1:];p="/tmp/mutation-state.json";s=json.load(open(p));s["containers"].append({"id":C,"name":"foreign","project":"other","service":"x","policy":"no","state":"exited","image":I,"mounts":[{"type":"volume","name":"app-data","source":"/v","destination":"/x","rw":True}],"networks":[]});json.dump(s,open(p,"w"))
PY
! /usr/local/sbin/vds-guardianctl purge-approved-compose-project >/tmp/reject 2>&1; test "$(mutations)" = 0
write_state; write_purge
python3 - <<"PY"
import json
p="/tmp/mutation-state.json";s=json.load(open(p));s["networks"]["orphan"]["extra_endpoints"]={"foreign":{}};json.dump(s,open(p,"w"))
PY
! /usr/local/sbin/vds-guardianctl purge-approved-compose-project >/tmp/reject 2>&1; test "$(mutations)" = 0
write_state; write_purge; chmod 0775 /root/textbee
! /usr/local/sbin/vds-guardianctl purge-approved-compose-project >/tmp/reject 2>&1; test "$(mutations)" = 0
write_state; write_purge; ln -s /tmp /root/textbee/unsafe-link
! /usr/local/sbin/vds-guardianctl purge-approved-compose-project >/tmp/reject 2>&1; test "$(mutations)" = 0
write_state; write_purge
python3 - <<"PY"
import json
p="/etc/vds-guardian/manifests/purge.json";m=json.load(open(p));m["image_ids"]=["1"*64];json.dump(m,open(p,"w"))
PY
chmod 0400 /etc/vds-guardian/manifests/purge.json
! /usr/local/sbin/vds-guardianctl purge-approved-compose-project >/tmp/reject 2>&1; test "$(mutations)" = 0
# Injected failure after the first mutation is safely resumable.
write_state; write_purge
python3 - <<"PY"
import json
p="/tmp/mutation-state.json";s=json.load(open(p));s["fail_mutation"]=2;json.dump(s,open(p,"w"))
PY
! /usr/local/sbin/vds-guardianctl purge-approved-compose-project >/tmp/injected 2>&1
python3 - <<"PY"
import json
p="/tmp/mutation-state.json";s=json.load(open(p));s.pop("fail_mutation");s["mutation_count"]=0;json.dump(s,open(p,"w"))
PY
/usr/local/sbin/vds-guardianctl purge-approved-compose-project
/usr/local/sbin/vds-guardianctl purge-approved-compose-project
python3 - "$P" <<"PY"
import json,sys
P=sys.argv[1:][0];s=json.load(open("/tmp/mutation-state.json"));assert not s["containers"] and not s["volumes"] and "orphan" not in s["networks"] and s["networks"]["protected"]["id"]==P and not s["images"]
PY
test ! -e /root/textbee
python3 - <<"PY"
l=open("/tmp/mutation-docker.log").read().splitlines();m=[x for x in l if x.startswith(("update ","stop ","rm ","volume rm","network rm","image rm"))];first=lambda p:next(i for i,x in enumerate(m) if x.startswith(p));assert first("update ")<first("stop ")<first("rm ")<first("volume rm")<first("network rm")<first("image rm")
PY
# If image removal fails after all targets are gone, the strict manifest keeps
# exact image identity durable: resume removes the exclusive image only.
write_state; write_purge
python3 - "$C" "$I" "$J" <<"PY"
import json,sys
C,I,J=sys.argv[1:];p="/tmp/mutation-state.json";s=json.load(open(p));s["containers"][1]["image"]=J;x=dict(s["containers"][0]);x.update(id=C,name="foreign",project="other",service="foreign",policy="no",state="exited",mounts=[],networks=[]);s["containers"].append(x);s["images"]=[I,J];s["fail_mutation"]=9;json.dump(s,open(p,"w"))
q="/etc/vds-guardian/manifests/purge.json";m=json.load(open(q));m["image_ids"]=[I,J];json.dump(m,open(q,"w"))
PY
chmod 0400 /etc/vds-guardian/manifests/purge.json
! /usr/local/sbin/vds-guardianctl purge-approved-compose-project >/tmp/image-injected 2>&1
python3 - "$C" "$I" "$J" <<"PY"
import json,sys
C,I,J=sys.argv[1:];p="/tmp/mutation-state.json";s=json.load(open(p));assert [x["id"] for x in s["containers"]]==[C] and set(s["images"])=={I,J};s.pop("fail_mutation");s["mutation_count"]=0;json.dump(s,open(p,"w"))
PY
/usr/local/sbin/vds-guardianctl purge-approved-compose-project
python3 - "$C" "$I" "$J" <<"PY"
import json,sys
C,I,J=sys.argv[1:];s=json.load(open("/tmp/mutation-state.json"));assert [x["id"] for x in s["containers"]]==[C] and s["images"]==[I]
PY
printf "%s\n" manifest_mutations_ok
'

# A separate, disposable test container receives CAP_SYS_ADMIN solely to prove
# that a same-filesystem nested bind mount (with mountinfo-escaped spaces) is
# rejected before any Docker or filesystem mutation.
docker run --rm --cap-add SYS_ADMIN --security-opt apparmor=unconfined -v "$ROOT:/repo:ro" "$IMAGE" bash /repo/tests/mount-boundary.sh
