#!/bin/bash
set -Eeuo pipefail
PATH='/usr/sbin:/usr/bin:/sbin:/bin'
umask 077
export LC_ALL=C

readonly HELPER_PATH='/usr/local/sbin/vds-guardianctl'
readonly SUDOERS_PATH='/etc/sudoers.d/vds-guardian'
readonly LOCK_PATH='/run/vds-guardian-upgrade.lock'
readonly BASELINE_V1_HELPER_SHA256='4a1d6c53954b5b88f5a7c01821377142f1e998dc37ac388a4e74d40729282e08'
readonly BASELINE_V1_SUDOERS_SHA256='125a74e6ffa5c50d3fecf8142cc7c5a1de3017e455a1c91f87e6f298c8309020'
readonly BASELINE_V2_HELPER_SHA256='7c2fe0ed76f2811b9905f1f975c1e8de526313c9466bfb32fd229a7e696e46ae'
readonly BASELINE_V2_SUDOERS_SHA256='3580b0d94eb24be1d5a18cab2e6bc40e83c7ec1c09c8fc552f97c595ab131341'
readonly BASELINE_V3_HELPER_SHA256='699c1c32b3397cd43302fe3a1a14ec3360e7f95427df8452f8735e61b182117d'
readonly BASELINE_V3_SUDOERS_SHA256='3580b0d94eb24be1d5a18cab2e6bc40e83c7ec1c09c8fc552f97c595ab131341'
readonly BASELINE_V4_HELPER_SHA256='42dbb4c4146cbb323fa807a7f35ca6e813d4af03bda027f5f2de9f4c5f1a2169'
readonly BASELINE_V4_SUDOERS_SHA256='37a03d5d96f9a149acc42240068bf7ddcc3ec766fb13667f87812e289b3e0d76'
# Exact source pair from commit 304d084 (fixtures vds-guardian{ctl,.sudoers}-304d084).
readonly BASELINE_V5_HELPER_SHA256='26a83ff99dfd63640b0a14d069fdeb0a8235b1c80fefa4d8168d6d3064084fbc'
readonly BASELINE_V5_SUDOERS_SHA256='d656075f924c9d5b047fa75c8072cdf99e399220b4e858fd435a36e492fb8004'
readonly NEW_HELPER_SHA256='dc4a0cdff43ce5d282e399b2d833a985312eb8f92af5b26ced90ebad5ad4a60d'
readonly NEW_SUDOERS_SHA256='4a3935103d445b7f8da04f72563fce3db0b25f00bcbfef661d6fef7d9f533198'

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

[[ ${EUID} -eq 0 ]] || fail 'run this upgrade as root (for example: sudo bash upgrade-existing.sh)'
[[ $# -eq 0 ]] || fail 'this upgrade accepts no arguments'

for command in bash cat cmp flock getent id install mktemp mv rm sha256sum stat visudo; do
  command -v "$command" >/dev/null 2>&1 || fail "required command is missing: $command"
done
[[ -x /usr/bin/python3 ]] || fail 'required interpreter is missing: /usr/bin/python3'

safe_dir() {
  local path=$1 metadata uid gid mode type mode_number
  [[ -d ${path} && ! -L ${path} ]] || return 1
  metadata=$(stat -c '%u:%g:%a:%F' -- "$path") || return 1
  IFS=: read -r uid gid mode type <<<"$metadata"
  [[ $uid == 0 && $gid == 0 && $type == directory ]] || return 1
  mode_number=$((8#$mode))
  (( (mode_number & 0022) == 0 ))
}

require_safe_dir() {
  safe_dir "$1" || fail "required parent is not a real root:root non-group/world-writable directory: $1"
}

safe_file() {
  local path=$1 expected_mode=$2 metadata
  [[ -f ${path} && ! -L ${path} ]] || return 1
  metadata=$(stat -c '%u:%g:%a:%F' -- "$path") || return 1
  [[ ${metadata} == "0:0:${expected_mode}:regular file" ]]
}

require_safe_file() {
  safe_file "$1" "$2" || fail "unsafe owner, mode, or type for required path: $1"
}

file_sha256() {
  local output
  output=$(sha256sum -- "$1") || fail "cannot hash file: $1"
  printf '%s\n' "${output%% *}"
}

require_helper_authority() {
  local helper=$1 sudoers=$2 digest
  digest=$(file_sha256 "$helper")
  grep -Fqx -- "# vds-guardianctl-sha256: $digest" "$sudoers" \
    || fail 'sudoers detached helper hash authority does not match helper'
}

require_all_parents() {
  local parent
  for parent in / /usr /usr/local /usr/local/sbin /etc /etc/sudoers.d; do
    require_safe_dir "$parent"
  done
}

require_installed_state() {
  local expected_helper=$1 expected_sudoers=$2
  require_all_parents
  require_safe_file "$HELPER_PATH" 755
  require_safe_file "$SUDOERS_PATH" 440
  [[ $(file_sha256 "$HELPER_PATH") == "$expected_helper" ]] || fail 'installed helper hash changed'
  [[ $(file_sha256 "$SUDOERS_PATH") == "$expected_sudoers" ]] || fail 'installed sudoers hash changed'
  if [[ $expected_helper == "$NEW_HELPER_SHA256" ]]; then
    require_helper_authority "$HELPER_PATH" "$SUDOERS_PATH"
  fi
}

# Validate the lock boundary before opening. / and /run are root-only writable,
# so an unprivileged process cannot race this check by replacing the fixed lock
# leaf or its path components.
require_safe_dir /
require_safe_dir /run
[[ ! -L $LOCK_PATH ]] || fail "upgrade lock must not be a symlink: $LOCK_PATH"
exec {lock_fd}>>"$LOCK_PATH" || fail "cannot open upgrade lock: $LOCK_PATH"
require_safe_dir /run
[[ -f $LOCK_PATH && ! -L $LOCK_PATH ]] || fail "upgrade lock is not a regular non-symlink file: $LOCK_PATH"
lock_metadata=$(stat -c '%u:%g:%a' -- "$LOCK_PATH") || fail 'cannot inspect upgrade lock'
IFS=: read -r lock_uid lock_gid lock_mode <<<"$lock_metadata"
lock_mode_number=$((8#$lock_mode))
[[ $lock_uid == 0 && $lock_gid == 0 ]] \
  || fail 'upgrade lock has unsafe owner'
(( (lock_mode_number & 0022) == 0 )) || fail 'upgrade lock is group/world writable'
flock -n "$lock_fd" || fail 'another guardian upgrade is already running'

# Nothing below inspects or hashes either target until this process owns the
# exclusive lock. The descriptor remains open through EXIT cleanup.
require_all_parents
require_safe_file "$HELPER_PATH" 755
require_safe_file "$SUDOERS_PATH" 440
current_helper_sha256=$(file_sha256 "$HELPER_PATH")
current_sudoers_sha256=$(file_sha256 "$SUDOERS_PATH")
selected_baseline_helper_sha256=''
selected_baseline_sudoers_sha256=''

getent passwd guardian >/dev/null || fail 'guardian account does not exist'
guardian_uid=$(id -u guardian) || fail 'cannot determine guardian uid'
[[ $guardian_uid != 0 ]] || fail 'guardian must not have uid 0'
guardian_primary_gid=$(id -g guardian) || fail 'cannot determine guardian primary gid'
[[ $guardian_primary_gid != 0 ]] || fail 'guardian must not have primary gid 0'
guardian_numeric_groups=$(id -G guardian) || fail 'cannot determine guardian numeric groups'
for group_id in $guardian_numeric_groups; do
  [[ $group_id != 0 ]] || fail 'guardian must not belong to numeric group 0'
done
guardian_groups=$(id -nG guardian) || fail 'cannot determine guardian groups'
[[ -n ${guardian_groups} ]] || fail 'guardian group list is empty'
for group in $guardian_groups; do
  case "$group" in
    guardian|users) ;;
    *) fail "guardian has an unexpected supplemental group: $group" ;;
  esac
done

tmpdir=$(mktemp -d)
mutation_started=0
committed=0
rollback_done=0

atomic_replace() {
  local source=$1 destination=$2 mode=$3 parent stage
  parent=${destination%/*}
  safe_dir "$parent" || return 1
  stage=$(mktemp "$parent/.vds-guardian-upgrade.XXXXXX") || return 1
  if ! install -m "$mode" -o root -g root -- "$source" "$stage"; then
    rm -f -- "$stage"
    return 1
  fi
  if ! safe_file "$stage" "${mode#0}"; then
    rm -f -- "$stage"
    return 1
  fi
  safe_dir "$parent" || { rm -f -- "$stage"; return 1; }
  mv -T -- "$stage" "$destination" || { rm -f -- "$stage"; return 1; }
}

rollback_and_verify() {
  local failed=0
  rollback_done=1
  printf '%s\n' 'ERROR: upgrade failed; restoring both original files' >&2
  atomic_replace "$tmpdir/original-helper" "$HELPER_PATH" 0755 \
    || { printf '%s\n' 'CRITICAL: failed to restore original helper' >&2; failed=1; }
  atomic_replace "$tmpdir/original-sudoers" "$SUDOERS_PATH" 0440 \
    || { printf '%s\n' 'CRITICAL: failed to restore original sudoers file' >&2; failed=1; }

  if ! safe_file "$HELPER_PATH" 755 \
    || [[ $(sha256sum -- "$HELPER_PATH" 2>/dev/null) != "$selected_baseline_helper_sha256  $HELPER_PATH" ]] \
    || ! bash -n "$HELPER_PATH"; then
    printf '%s\n' 'CRITICAL: restored helper failed metadata, hash, or syntax verification' >&2
    failed=1
  fi
  if ! safe_file "$SUDOERS_PATH" 440 \
    || [[ $(sha256sum -- "$SUDOERS_PATH" 2>/dev/null) != "$selected_baseline_sudoers_sha256  $SUDOERS_PATH" ]] \
    || ! visudo -cf "$SUDOERS_PATH"; then
    printf '%s\n' 'CRITICAL: restored sudoers failed metadata, hash, or visudo verification' >&2
    failed=1
  fi
  return "$failed"
}

cleanup() {
  local status=$? rollback_status=0
  trap - EXIT INT TERM HUP
  if [[ ${mutation_started} -eq 1 && ${committed} -eq 0 && ${rollback_done} -eq 0 ]]; then
    rollback_and_verify || rollback_status=$?
  fi
  rm -rf -- "$tmpdir" || { printf '%s\n' 'CRITICAL: failed to remove upgrade temporary directory' >&2; rollback_status=1; }
  if (( status == 0 && rollback_status != 0 )); then
    status=1
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

cat >"$tmpdir/new-helper" <<'VDS_GUARDIAN_HELPER'
#!/bin/bash
set -Eeuo pipefail
PATH='/usr/sbin:/usr/bin:/sbin:/bin'
umask 077
export LC_ALL=C
export HOME='/root'
export USER='root'
export LOGNAME='root'
export SYSTEMD_PAGER='cat'
export SYSTEMD_COLORS='0'
unset BASH_ENV ENV CDPATH DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG PAGER LESS

readonly SELF='/usr/local/sbin/vds-guardianctl'

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

section() {
  printf '\n=== %s ===\n' "$1"
}

have() {
  command -v "$1" >/dev/null 2>&1
}

require_root_and_integrity() {
  [[ ${EUID} -eq 0 ]] || fail 'must run through the approved sudo rule'
  [[ $# -eq 1 ]] || fail 'exactly one fixed action is required'
  [[ -f ${SELF} && ! -L ${SELF} ]] || fail 'helper path is missing or is a symlink'
  local owner mode
  owner=$(stat -c '%U:%G' "${SELF}")
  mode=$(stat -c '%a' "${SELF}")
  [[ ${owner} == 'root:root' ]] || fail 'helper must be owned by root:root'
  [[ ${mode} == '755' ]] || fail 'helper mode must be 0755'
}

show_docker_inventory() {
  if ! have docker; then
    printf '%s\n' 'docker: not installed'
    return
  fi
  if ! docker info >/dev/null 2>&1; then
    printf '%s\n' 'docker: installed, daemon unavailable'
    return
  fi
  docker ps -a --no-trunc --format 'container={{.Names}} image={{.Image}} status={{.Status}} ports={{.Ports}}'
  docker system df
}

audit_compose_projects() {
  have docker || fail 'docker is not installed'
  docker info >/dev/null 2>&1 || fail 'docker daemon is unavailable'

  local ids id
  section 'docker containers'
  docker ps -a --no-trunc --format 'id={{printf "%q" .ID}} name={{printf "%q" .Names}} image={{printf "%q" .Image}} state={{printf "%q" .State}} status={{printf "%q" .Status}}' \
    || fail 'could not list docker containers'
  ids=$(docker ps -aq --no-trunc) || fail 'could not collect docker container IDs'
  if [[ -n ${ids} ]]; then
    while IFS= read -r id; do
      [[ -n ${id} ]] || continue
      docker inspect --type container --format 'id={{printf "%q" .Id}} name={{printf "%q" .Name}} image={{printf "%q" .Config.Image}} image_id={{printf "%q" .Image}} state={{printf "%q" .State.Status}} restart_policy={{printf "%q" .HostConfig.RestartPolicy.Name}}
compose_project={{printf "%q" (index .Config.Labels "com.docker.compose.project")}} compose_service={{printf "%q" (index .Config.Labels "com.docker.compose.service")}} compose_working_dir={{printf "%q" (index .Config.Labels "com.docker.compose.project.working_dir")}} compose_config_files={{printf "%q" (index .Config.Labels "com.docker.compose.project.config_files")}} compose_oneoff={{printf "%q" (index .Config.Labels "com.docker.compose.oneoff")}} compose_version={{printf "%q" (index .Config.Labels "com.docker.compose.version")}}
{{range .Mounts}}mount type={{printf "%q" .Type}} name={{printf "%q" (or (index . "Name") "")}} source={{printf "%q" .Source}} destination={{printf "%q" .Destination}} rw={{.RW}}
{{end}}{{range $name, $network := .NetworkSettings.Networks}}network name={{printf "%q" $name}} id={{printf "%q" $network.NetworkID}}
{{end}}' "${id}" || fail "could not inspect docker container ${id}"
    done <<<"${ids}"
  fi

  section 'docker volumes'
  ids=$(docker volume ls -q) || fail 'could not list docker volumes'
  if [[ -n ${ids} ]]; then
    while IFS= read -r id; do
      [[ -n ${id} ]] || continue
      docker volume inspect --format 'id={{printf "%q" .Name}} name={{printf "%q" .Name}} driver={{printf "%q" .Driver}} scope={{printf "%q" .Scope}} internal=n/a
compose_project={{printf "%q" (index .Labels "com.docker.compose.project")}} compose_volume={{printf "%q" (index .Labels "com.docker.compose.volume")}} compose_version={{printf "%q" (index .Labels "com.docker.compose.version")}}' "${id}" \
        || fail "could not inspect docker volume ${id}"
    done <<<"${ids}"
  fi

  section 'docker networks'
  ids=$(docker network ls -q --no-trunc) || fail 'could not list docker networks'
  if [[ -n ${ids} ]]; then
    while IFS= read -r id; do
      [[ -n ${id} ]] || continue
      docker network inspect --format 'id={{printf "%q" .Id}} name={{printf "%q" .Name}} driver={{printf "%q" .Driver}} scope={{printf "%q" .Scope}} internal={{.Internal}}
compose_project={{printf "%q" (index .Labels "com.docker.compose.project")}} compose_network={{printf "%q" (index .Labels "com.docker.compose.network")}} compose_version={{printf "%q" (index .Labels "com.docker.compose.version")}}' "${id}" \
        || fail "could not inspect docker network ${id}"
    done <<<"${ids}"
  fi
}

audit_storage() {
  section 'identity'
  hostname --fqdn 2>/dev/null || hostname
  printf 'time_utc=%s\n' "$(date -u +%FT%TZ)"

  section 'filesystems'
  df -hPT
  df -iP

  section 'top-level usage in bytes (same filesystem only)'
  du -x -B1 --max-depth=1 / 2>/dev/null | sort -n || true

  section 'package cache'
  if [[ -d /var/cache/apt/archives ]]; then
    du -sB1 /var/cache/apt/archives 2>/dev/null || true
  else
    printf '%s\n' 'apt cache: not present'
  fi

  section 'journal usage'
  if have journalctl; then
    journalctl --disk-usage || true
  else
    printf '%s\n' 'journalctl: not installed'
  fi

  section 'old regular files in system temp directories (aggregate only)'
  if have find; then
    find /tmp /var/tmp -xdev -type f -mtime +7 -printf '%s\n' 2>/dev/null | awk '{n+=1; b+=$1} END {printf "files=%d bytes=%d\n", n, b}'
  fi

  section 'deleted but open files'
  if have lsof; then
    lsof -nP +L1 2>/dev/null || true
  else
    printf '%s\n' 'lsof: not installed'
  fi

  section 'docker storage summary'
  show_docker_inventory
}

audit_root_storage() {
  [[ -x /usr/bin/python3 ]] || fail 'python3 is required'
  /usr/bin/python3 - <<'PY'
import datetime,fcntl,hashlib,io,os,re,stat,sys,time
ROOT=b'/root'; DIR=os.O_RDONLY|os.O_CLOEXEC|os.O_DIRECTORY|os.O_NOFOLLOW; FILE=os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW
SUBTREE_MAX_ENTRIES=250000; GLOBAL_MAX_ENTRIES=500000; MAX_DEPTH=64; MAX_SECONDS=120; MAX_REPORT=8388608; TOP_N=64; LIST_MAX=50
AUTH=re.compile(rb'^# vds-guardianctl-sha256: ([0-9a-f]{64})$')
SENSITIVE=re.compile(rb'(?:^\.|secret|token|pass(?:word)?|credential|private|auth|cookie|session|mnemonic|wallet|vault|seed|api[-_.]?key|ssh|gnupg|kubeconfig|id_(?:rsa|dsa|ecdsa|ed25519)|service[-_.]?account|\.env(?:\.|$)|(?:^|[-_.])(?:key|pem|p12|pfx|keystore)(?:[-_.]|$))',re.I)
CATEGORIES=('cache','backups','Git','logs','temp')
class Bad(Exception):pass
class SubtreeLimit(Exception):pass
class GlobalLimit(Exception):
 def __init__(self,reason):
  self.reason=reason;Exception.__init__(self,reason)
class DepthLimit(Exception):pass
def bad(s):raise Bad(s)
def metadata(s,d,m=None):
 return s.st_uid==s.st_gid==0 and ((stat.S_ISDIR(s.st_mode) and not s.st_mode&0o022) if d else (stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode)==m))
def chain(parts,mode=None):
 f=[]
 try:
  x=os.open(b'/',DIR);f.append(x)
  if not metadata(os.fstat(x),True):bad('unsafe trusted directory metadata')
  for i,p in enumerate(parts):
   leaf=i==len(parts)-1 and mode is not None;x=os.open(p,FILE if leaf else DIR,dir_fd=x);f.append(x)
   if not metadata(os.fstat(x),not leaf,mode):bad('unsafe trusted path metadata')
  return f
 except:
  for x in reversed(f):os.close(x)
  raise
def readfd(fd,n,label):
 out=[];size=0
 while True:
  b=os.read(fd,min(65536,n+1-size))
  if not b:return b''.join(out)
  out.append(b);size+=len(b)
  if size>n:bad(label+' is too large')
def precheck():
 h=chain([b'usr',b'local',b'sbin',b'vds-guardianctl'],0o755);s=chain([b'etc',b'sudoers.d',b'vds-guardian'],0o440)
 try:
  hb=readfd(h[-1],1048576,'helper');sb=readfd(s[-1],65536,'sudoers authority');ds=[]
  for line in sb.splitlines():
   m=AUTH.fullmatch(line)
   if m:ds.append(m.group(1))
  if len(ds)!=1:bad('sudoers helper authority is missing or ambiguous')
  if hashlib.sha256(hb).hexdigest().encode()!=ds[0]:bad('helper does not match the sudoers hash authority')
 finally:
  for x in reversed(h+s):os.close(x)
def unescape(v):
 out=bytearray();i=0
 while i<len(v):
  if v[i:i+1]!=b'\\':out.append(v[i]);i+=1;continue
  e=v[i+1:i+4]
  if len(e)!=3 or any(c<48 or c>55 for c in e):bad('malformed mount boundary inventory')
  out.append(int(e,8));i+=4
 return bytes(out)
def mounts():
 try:
  fd=os.open(b'/proc/self/mountinfo',FILE)
  try:data=readfd(fd,8388608,'mount boundary inventory')
  finally:os.close(fd)
 except OSError:bad('cannot inspect mount boundaries')
 out=set()
 for line in data.splitlines():
  f=line.split(b' ')
  if len(f)<10 or b'-' not in f[6:]:bad('malformed mount boundary inventory')
  p=unescape(f[4])
  if not p.startswith(b'/') or b'\0' in p:bad('malformed mount boundary path')
  out.add(p)
 if b'/' not in out:bad('incomplete mount boundary inventory')
 return out,data
def lock():
 f=chain([b'run'])
 try:
  x=os.open(b'vds-guardian-audit-root-storage.lock',os.O_RDWR|os.O_CREAT|os.O_CLOEXEC|os.O_NOFOLLOW,0o600,dir_fd=f[-1]);s=os.fstat(x)
  if not metadata(s,False,0o600):os.close(x);bad('unsafe audit lock metadata')
  try:fcntl.flock(x,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError:os.close(x);bad('another root storage audit is already running')
  return x
 finally:
  for x in reversed(f):os.close(x)
def names(fd,reserve,check):
 try:
  with os.scandir(fd) as it:
   a=[]
   for x in it:
    reserve()
    a.append(os.fsencode(x.name))
   check()
   a.sort()
   check()
 except OSError:bad('directory enumeration failed')
 if any(not x or x in (b'.',b'..') or b'/' in x or b'\0' in x for x in a):bad('unsafe directory entry name')
 return a
def shown(n):
 return n.decode() if not SENSITIVE.search(n) and re.fullmatch(rb'[A-Za-z0-9][A-Za-z0-9._+-]{0,127}',n) else '<redacted>'
def categories(n):
 n=n.lower();r=set()
 if n in (b'cache',b'caches',b'.cache') or b'cache' in n:r.add('cache')
 if n in (b'backup',b'backups',b'archive',b'archives',b'snapshot',b'snapshots') or n.endswith((b'.bak',b'.backup',b'.old',b'.tar',b'.tgz',b'.gz',b'.bz2',b'.xz',b'.zip',b'.7z')):r.add('backups')
 if n in (b'log',b'logs') or n.endswith((b'.log',b'.log.1')):r.add('logs')
 if n in (b'tmp',b'temp',b'temporary') or n.endswith((b'.tmp',b'.swp',b'~')):r.add('temp')
 return r
def ftype(m):
 for p,n in ((stat.S_ISREG,'regular'),(stat.S_ISDIR,'directory'),(stat.S_ISLNK,'symlink'),(stat.S_ISBLK,'block'),(stat.S_ISCHR,'character'),(stat.S_ISFIFO,'fifo'),(stat.S_ISSOCK,'socket')):
  if p(m):return n
 return 'other'
def mtime(s):
 try:return datetime.datetime.fromtimestamp(s.st_mtime_ns//1000000000,datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
 except (OverflowError,OSError,ValueError):bad('unrepresentable object mtime')
def add_reason(current,new):
 return '+'.join(dict.fromkeys(filter(None,(current+'+'+new).split('+'))))
class Scanner:
 def __init__(self,m,d):
  self.mounts=m;self.dev=d;self.count=0;self.sub_count=0;self.sub_exhausted=False;self.global_stop=False;self.stop_reason=''
  self.deadline=time.monotonic()+MAX_SECONDS;self.totals={x:0 for x in CATEGORIES};self.files=set();self.category_files={x:set() for x in CATEGORIES}
 def check(self):
  if time.monotonic()>self.deadline:raise GlobalLimit('time_limit')
 def reserve_global(self):
  self.count+=1
  if self.count>GLOBAL_MAX_ENTRIES:raise GlobalLimit('entry_limit')
  self.check()
 def reserve_sub(self):
  self.sub_count+=1;self.count+=1
  if self.sub_count>SUBTREE_MAX_ENTRIES:raise SubtreeLimit()
  if self.count>GLOBAL_MAX_ENTRIES:raise GlobalLimit('entry_limit')
  self.check()
 def node(self,fd,n,path,label,depth,active):
  self.check()
  if depth>MAX_DEPTH:raise DepthLimit()
  if path in self.mounts and path!=ROOT:return {'excluded':'mount'}
  try:s=os.stat(n,dir_fd=fd,follow_symlinks=False)
  except OSError:bad('object metadata read failed')
  if s.st_dev!=self.dev:bad('object crossed an unrecorded mount boundary')
  active=set(active)|categories(n);allocated=s.st_blocks*512
  key=(s.st_dev,s.st_ino) if stat.S_ISREG(s.st_mode) else None
  if key is not None:
   if key in self.files:allocated=0
   else:self.files.add(key)
  total=allocated;status='complete';reason=''
  if stat.S_ISDIR(s.st_mode):
   try:c=os.open(n,DIR,dir_fd=fd)
   except OSError:bad('directory open failed')
   try:
    a=os.fstat(c)
    if (a.st_dev,a.st_ino,a.st_mode)!=(s.st_dev,s.st_ino,s.st_mode):bad('directory changed during traversal')
    ns=names(c,self.reserve_sub,self.check)
    if b'.git' in ns:active.add('Git')
    for cn in ns:
     child=self.node(c,cn,path+b'/'+cn,label+'/'+shown(cn),depth+1,active)
     if child is None:continue
     if child.get('excluded')=='mount':
      status='partial';reason=add_reason(reason,'mount')
      continue
     total+=child['size']
     if child['status']=='partial':
      status='partial';reason=add_reason(reason,child['reason'])
     if self.sub_exhausted or self.global_stop:break
   except SubtreeLimit:
    status='partial';reason=add_reason(reason,'entry_limit');self.sub_exhausted=True
   except DepthLimit:
    status='partial';reason=add_reason(reason,'depth_limit')
   except GlobalLimit as e:
    status='partial';reason=add_reason(reason,'global_'+e.reason);self.global_stop=True;self.stop_reason=e.reason
   finally:os.close(c)
  for x in active:
   if key is None:self.totals[x]+=s.st_blocks*512
   elif key not in self.category_files[x]:self.category_files[x].add(key);self.totals[x]+=s.st_blocks*512
  return {'path':label,'size':total,'status':status,'reason':reason,'owner':'%d:%d'%(s.st_uid,s.st_gid),'mode':'0%o'%stat.S_IMODE(s.st_mode),'type':ftype(s.st_mode),'mtime':mtime(s)}
def line(n):
 size_key='size_lower_bound' if n['status']=='partial' else 'size'
 s='path=%s %s=%d status=%s owner=%s mode=%s type=%s mtime=%s'%(n['path'],size_key,n['size'],n['status'],n['owner'],n['mode'],n['type'],n['mtime'])
 if n['status']=='partial':s+=' reason=%s entries=%d'%(n['reason'],n['entries'])
 return s+'\n'
def audit(fd,mounts):
 sc=Scanner(mounts,os.fstat(fd).st_dev);completed=[];partials=[];excluded=[];not_audited=[]
 try:
  top=names(fd,sc.reserve_global,sc.check)
 except GlobalLimit as e:
  sc.global_stop=True;sc.stop_reason=e.reason;top=[]
 for n in top:
  if sc.global_stop:
   not_audited.append('/root/'+shown(n));continue
  sc.sub_count=0;sc.sub_exhausted=False
  try:
   x=sc.node(fd,n,ROOT+b'/'+n,'/root/'+shown(n),1,set())
  except GlobalLimit as e:
   sc.global_stop=True;sc.stop_reason=e.reason
   not_audited.append('/root/'+shown(n));continue
  if x is None:continue
  if x.get('excluded')=='mount':
   excluded.append({'path':'/root/'+shown(n),'reason':'mount'});continue
  if x['status']=='partial':
   x['entries']=sc.sub_count;partials.append(x)
  else:completed.append(x)
 out=io.StringIO()
 out.write('audit=root-storage progressive=1 limits subtree=%d global=%d depth=%d top=%d\n'%(SUBTREE_MAX_ENTRIES,GLOBAL_MAX_ENTRIES,MAX_DEPTH,TOP_N))
 # When the global budget or deadline expires before top-level enumeration
 # completes, the number of unvisited top-level subtrees is unknown, so the
 # summary reports the literal sentinel 'unbounded' instead of a fake count.
 na='unbounded' if (sc.global_stop and not top) else str(len(not_audited))
 out.write('summary completed=%d partial=%d excluded=%d not_audited=%s entries=%d\n'%(len(completed),len(partials),len(excluded),na,sc.count))
 if sc.global_stop:out.write('limit=%s\n'%sc.stop_reason)
 completed.sort(key=lambda x:x['size'],reverse=True)
 for x in completed[:TOP_N]:out.write(line(x))
 partials.sort(key=lambda x:x['size'],reverse=True)
 for x in partials[:LIST_MAX]:out.write(line(x))
 if len(partials)>LIST_MAX:out.write('partial_more=%d\n'%(len(partials)-LIST_MAX))
 for x in excluded[:LIST_MAX]:out.write('excluded path=%s reason=mount\n'%x['path'])
 if len(excluded)>LIST_MAX:out.write('excluded_more=%d\n'%(len(excluded)-LIST_MAX))
 for p in not_audited[:LIST_MAX]:out.write('not_audited path=%s\n'%p)
 if len(not_audited)>LIST_MAX:out.write('not_audited_more=%d\n'%(len(not_audited)-LIST_MAX))
 cat_status='complete' if (not partials and not excluded and not not_audited and not sc.global_stop) else 'partial'
 cat_size_key='size' if cat_status=='complete' else 'size_lower_bound'
 for c in CATEGORIES:out.write('category=%s %s=%d status=%s\n'%(c,cat_size_key,sc.totals[c],cat_status))
 data=out.getvalue().encode('ascii')
 if len(data)>MAX_REPORT:bad('root storage audit output limit exceeded')
 return data
def main():
 if os.geteuid()!=0:bad('must run through the approved sudo rule')
 precheck();lf=lock();rf=[]
 try:
  mp,mi=mounts();rf=chain([b'root']);data=audit(rf[-1],mp)
  mp2,mi2=mounts()
  if mp2!=mp or mi2!=mi:bad('mount boundary inventory changed during audit')
  while data:data=data[os.write(1,data):]
 finally:
  for x in reversed(rf):os.close(x)
  os.close(lf)
try:main()
except Bad as message:print('ERROR: '+str(message),file=sys.stderr);sys.exit(1)
except Exception:print('ERROR: root storage audit failed',file=sys.stderr);sys.exit(1)
PY
}

audit_services() {
  section 'identity and uptime'
  hostname --fqdn 2>/dev/null || hostname
  uptime

  section 'failed systemd units'
  if have systemctl; then
    systemctl --failed --no-pager || true
  fi

  section 'running services'
  if have systemctl; then
    systemctl list-units --type=service --state=running --no-pager --no-legend || true
  fi

  section 'timers'
  if have systemctl; then
    systemctl list-timers --all --no-pager || true
  fi

  section 'listeners'
  if have ss; then
    ss -lntup
  fi

  section 'docker containers and storage'
  show_docker_inventory
}

audit_security() {
  section 'operating system'
  if [[ -r /etc/os-release ]]; then
    sed -n 's/^\(PRETTY_NAME\|VERSION_ID\|ID\)=/\1=/p' /etc/os-release
  fi
  uname -r

  section 'listening sockets'
  if have ss; then
    ss -lntup
  fi

  section 'effective sshd policy (selected non-secret fields)'
  if have sshd; then
    sshd -T 2>/dev/null | awk '$1 ~ /^(port|listenaddress|permitrootlogin|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|maxauthtries|allowusers|allowgroups|denyusers|denygroups|x11forwarding|allowtcpforwarding|gatewayports|loglevel)$/ {print}' || true
  else
    printf '%s\n' 'sshd: not installed or unavailable'
  fi

  section 'firewall'
  if have ufw; then
    ufw status verbose || true
  elif have nft; then
    nft list ruleset || true
  elif have iptables; then
    iptables -S || true
  else
    printf '%s\n' 'firewall tooling: not detected'
  fi

  section 'brute-force protection'
  if have fail2ban-client; then
    fail2ban-client status || true
  else
    printf '%s\n' 'fail2ban: not detected'
  fi

  section 'automatic security updates'
  if have systemctl; then
    systemctl is-enabled unattended-upgrades.service 2>/dev/null || true
    systemctl is-active unattended-upgrades.service 2>/dev/null || true
  fi

  section 'backup-related timers (names only)'
  if have systemctl; then
    systemctl list-timers --all --no-pager --no-legend 2>/dev/null | grep -Ei 'backup|restic|borg|duplicity|rclone|snapshot|dump' || printf '%s\n' 'no matching timer names detected'
  fi

  section 'docker exposure summary'
  show_docker_inventory
}

verify_health() {
  section 'disk and inodes'
  df -hPT
  df -iP

  section 'failed systemd units'
  if have systemctl; then
    systemctl --failed --no-pager || true
  fi

  section 'listeners'
  if have ss; then
    ss -lntup
  fi

  section 'docker containers'
  if have docker && docker info >/dev/null 2>&1; then
    docker ps -a --no-trunc --format 'container={{.Names}} image={{.Image}} status={{.Status}} ports={{.Ports}}'
  else
    printf '%s\n' 'docker: absent or daemon unavailable'
  fi
}

clean_apt_cache() {
  have apt-get || fail 'apt-get is not installed'
  local before after
  before=$(du -sB1 /var/cache/apt/archives 2>/dev/null | awk '{print $1+0}')
  apt-get clean
  after=$(du -sB1 /var/cache/apt/archives 2>/dev/null | awk '{print $1+0}')
  printf 'action=clean-apt-cache before_bytes=%d after_bytes=%d reclaimed_bytes=%d\n' "${before:-0}" "${after:-0}" "$(( ${before:-0} - ${after:-0} ))"
}

vacuum_journal_30d() {
  have journalctl || fail 'journalctl is not installed'
  journalctl --disk-usage
  journalctl --vacuum-time=30d
  journalctl --disk-usage
}

clean_tmpfiles() {
  have systemd-tmpfiles || fail 'systemd-tmpfiles is not installed'
  systemd-tmpfiles --clean
  printf '%s\n' 'action=clean-tmpfiles completed'
}

clean_docker_build_cache_30d() {
  have docker || fail 'docker is not installed'
  docker info >/dev/null 2>&1 || fail 'docker daemon is unavailable'
  docker builder prune --force --filter 'until=720h'
}

manifest_mutation() {
  [[ -x /usr/bin/python3 && -x /usr/bin/docker ]] || fail 'python3 and docker are required'
  /usr/bin/python3 - "$1" "$2" <<'PY'
import fcntl,json,os,re,stat,subprocess,sys
D='/usr/bin/docker'; ID=re.compile(r'^[0-9a-f]{64}$'); NAME=re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$')
SLOTS={'purge':('/etc/vds-guardian/manifests/purge.json','purge-approved-compose-project'),'quiesce':('/etc/vds-guardian/manifests/quiesce.json','quiesce-approved-compose-project'),'remove':('/home/guardian/.vds-guardian/remove-containers.json','remove-containers-preserve-data')}
class Bad(Exception): pass
def bad(s): raise Bad(s)
def run(*a,js=False,missing=False):
 r=subprocess.run([D,*a],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,shell=False,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'},timeout=120)
 if r.returncode:
  if missing:
   err=' '.join(r.stderr.strip().split()).lower()
   target=a[-1].lower()
   proven=(a[:3]==('inspect','--type','container') and err in {'error: no such container: '+target,'error response from daemon: no such container: '+target}) or (a[:2]==('volume','inspect') and err in {'error response from daemon: get '+target+': no such volume','error: no such volume: '+target}) or (a[:2]==('network','inspect') and err in {'error response from daemon: network '+target+' not found','error: no such network: '+target}) or (a[:2]==('image','inspect') and err in {'error response from daemon: no such image: '+target,'error response from daemon: no such image: sha256:'+target,'error: no such image: '+target})
   if proven:return None
  bad('docker command failed: '+' '.join(a[:2]))
 if js:
  try:return json.loads(r.stdout)
  except ValueError:bad('docker returned malformed JSON')
 return r.stdout
def pairs(p):
 d={}
 for k,v in p:
  if k in d:bad('duplicate JSON key: '+k)
  d[k]=v
 return d
def keys(o,want,where):
 if type(o) is not dict or set(o)!=set(want):bad(where+' has missing or unknown keys')
def text(v,w,pat=None):
 if type(v) is not str or not v or len(v)>4096 or '\0' in v or (pat and not pat.fullmatch(v)):bad(w+' is invalid')
 return v
def optional_name(v,w):
 if type(v) is not str or len(v)>128 or (v and not NAME.fullmatch(v)):bad(w+' is invalid')
 return v
def fid(v,w):return text(v,w,ID)
def image_id(v,w):
 v=text(v,w);v=v.removeprefix('sha256:')
 return fid(v,w)
def uniq(a,key,w):
 if len(a)!=len({key(x) for x in a}):bad(w+' contains duplicates')
def manifest_bytes(path):
 cur='/'
 for part in path.strip('/').split('/'):
  cur=os.path.join(cur,part); s=os.lstat(cur)
  if stat.S_ISLNK(s.st_mode) or s.st_uid or s.st_gid:bad('unsafe manifest ownership or symlink')
  if cur!=path and (not stat.S_ISDIR(s.st_mode) or s.st_mode&0o022):bad('unsafe manifest parent')
  if cur==path and (not stat.S_ISREG(s.st_mode) or stat.S_IMODE(s.st_mode)!=0o400):bad('manifest must be root:root 0400 regular file')
 fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
 try:
  s=os.fstat(fd)
  if s.st_uid or s.st_gid or stat.S_IMODE(s.st_mode)!=0o400:bad('manifest changed while opening')
  b=os.read(fd,1048577)
  if len(b)>1048576:bad('manifest too large')
  return b
 finally:os.close(fd)
def request_bytes(path):
 try:
  import pwd
  guardian=pwd.getpwnam('guardian');uid=guardian.pw_uid;gid=guardian.pw_gid
 except (KeyError,ImportError):bad('guardian account is unavailable')
 expected=[('/',0,0,None),('/home',0,0,None),('/home/guardian',uid,gid,None),('/home/guardian/.vds-guardian',uid,gid,0o700)]
 fds=[]
 try:
  fd=os.open('/',os.O_RDONLY|os.O_CLOEXEC|os.O_DIRECTORY|os.O_NOFOLLOW);fds.append(fd)
  for full,eu,eg,emode in expected:
   if full!='/':
    fd=os.open(full.rsplit('/',1)[1],os.O_RDONLY|os.O_CLOEXEC|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);fds.append(fd)
   s=os.fstat(fd)
   if not stat.S_ISDIR(s.st_mode) or s.st_uid!=eu or s.st_gid!=eg or s.st_mode&0o022 or (emode is not None and stat.S_IMODE(s.st_mode)!=emode):bad('unsafe guardian request parent')
  fd=os.open('remove-containers.json',os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=fd);fds.append(fd);s=os.fstat(fd)
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=uid or s.st_gid!=gid or stat.S_IMODE(s.st_mode)!=0o600:bad('request must be guardian-owned mode 0600 regular file')
  b=os.read(fd,1048577)
  if len(b)>1048576:bad('request too large')
  return b
 except OSError as e:bad('malformed or unsafe request: '+str(e))
 finally:
  for fd in reversed(fds):os.close(fd)
def container(o,w,topology=False,image=False):
 want={'id','name','project','service','restart_policy'}|({'mounts','networks'} if topology else set())|({'image_id','auto_remove'} if image else set());keys(o,want,w)
 c={k:text(o[k],w+'.'+k,ID if k=='id' else NAME if k in {'name','project','service'} else None) for k in ['id','name','project','service','restart_policy']}
 if c['restart_policy'] not in {'no','always','on-failure','unless-stopped'}:bad(w+' restart policy invalid')
 if image:
  if type(o['auto_remove']) is not bool:bad(w+' auto_remove invalid')
  c['image_id']=fid(o['image_id'],w+'.image_id');c['auto_remove']=o['auto_remove']
  if c['auto_remove']:bad(w+' auto-remove containers cannot be safely stopped while preserving data')
 if topology:
  if type(o['mounts']) is not list or type(o['networks']) is not list:bad(w+' topology is not arrays')
  c['mounts']=[]
  for i,m in enumerate(o['mounts']):
   keys(m,{'type','name','source','destination','rw'},w+'.mounts')
   if m['type'] not in {'bind','volume','tmpfs'} or type(m['rw']) is not bool:bad(w+' mount invalid')
   for k in ['name','source','destination']:
    if type(m[k]) is not str or '\0' in m[k]:bad(w+' mount string invalid')
   if not m['destination'].startswith('/') or (m['type']=='volume') != bool(NAME.fullmatch(m['name'])):bad(w+' mount identity invalid')
   c['mounts'].append({k:m[k] for k in ['type','name','source','destination','rw']})
  c['networks']=[]
  for n in o['networks']:
   keys(n,{'id','name'},w+'.networks');c['networks'].append({'id':fid(n['id'],w+'.network.id'),'name':text(n['name'],w+'.network.name',NAME)})
  uniq(c['mounts'],lambda x:x['destination'],w+' mounts');uniq(c['networks'],lambda x:x['id'],w+' networks');uniq(c['networks'],lambda x:x['name'],w+' networks')
 return c
def network(o,w):
 keys(o,{'id','name','driver','scope','internal','project','compose_network'},w)
 if type(o['internal']) is not bool:bad(w+' internal invalid')
 return {'id':fid(o['id'],w+'.id'),'name':text(o['name'],w+'.name',NAME),'driver':text(o['driver'],w+'.driver',NAME),'scope':text(o['scope'],w+'.scope',NAME),'internal':o['internal'],'project':optional_name(o['project'],w+'.project'),'compose_network':optional_name(o['compose_network'],w+'.compose_network')}
def load(mode,path,action):
 try:o=json.loads((request_bytes(path) if mode=='remove' else manifest_bytes(path)).decode(),object_pairs_hook=pairs,parse_constant=lambda x:bad('invalid JSON number'))
 except (ValueError,UnicodeError,OSError) as e:bad('malformed or unsafe input: '+str(e))
 extra={'volumes','orphan_network','protected_networks','config_directory','image_ids'} if mode=='purge' else {'volumes','networks'} if mode=='remove' else set();keys(o,{'schema','action','containers'}|extra,'request' if mode=='remove' else 'manifest')
 if type(o['schema']) is not int or o['schema']!=1 or o['action']!=action:bad('wrong manifest schema or action')
 if type(o['containers']) is not list or not 1<=len(o['containers'])<=128:bad('invalid container count')
 cs=[container(x,'containers[%d]'%i,mode in {'purge','remove'},mode=='remove') for i,x in enumerate(o['containers'])];uniq(cs,lambda x:x['id'],'containers');uniq(cs,lambda x:x['name'],'containers');m={'containers':cs}
 if mode=='quiesce':return m
 if mode=='remove':
  if type(o['volumes']) is not list or len(o['volumes'])>256 or type(o['networks']) is not list or len(o['networks'])>256:bad('invalid preservation inventory')
  vs=[]
  for v in o['volumes']:
   keys(v,{'name','driver','scope','project','compose_volume'},'volume');vs.append({'name':text(v['name'],'volume.name',NAME),'driver':text(v['driver'],'volume.driver',NAME),'scope':text(v['scope'],'volume.scope',NAME),'project':optional_name(v['project'],'volume.project'),'compose_volume':optional_name(v['compose_volume'],'volume.compose_volume')})
  ns=[network(x,'network') for x in o['networks']];uniq(vs,lambda x:x['name'],'volumes');uniq(ns,lambda x:x['id'],'networks');uniq(ns,lambda x:x['name'],'networks')
  mounted={x['name'] for c in cs for x in c['mounts'] if x['type']=='volume'};attached={(x['id'],x['name']) for c in cs for x in c['networks']}
  if mounted!={x['name'] for x in vs}:bad('declared volumes do not exactly match container mounts')
  if attached!={(x['id'],x['name']) for x in ns}:bad('declared networks do not exactly match container topology')
  m.update(volumes=vs,networks=ns);return m
 if type(o['volumes']) is not list or not 1<=len(o['volumes'])<=128:bad('invalid volume count')
 vs=[]
 for v in o['volumes']:
  keys(v,{'name','driver','scope','project','compose_volume'},'volume');vs.append({'name':text(v['name'],'volume.name',NAME),'driver':text(v['driver'],'volume.driver',NAME),'scope':text(v['scope'],'volume.scope',NAME),'project':optional_name(v['project'],'volume.project'),'compose_volume':optional_name(v['compose_volume'],'volume.compose_volume')})
 uniq(vs,lambda x:x['name'],'volumes'); pn=[network(x,'protected_network') for x in o['protected_networks']] if type(o['protected_networks']) is list and o['protected_networks'] else bad('protected networks required'); on=network(o['orphan_network'],'orphan_network')
 if type(o['image_ids']) is not list or not 1<=len(o['image_ids'])<=128:bad('invalid image count')
 images=[fid(x,'image_ids') for x in o['image_ids']];uniq(images,lambda x:x,'images')
 uniq(pn+[on],lambda x:x['id'],'networks');uniq(pn+[on],lambda x:x['name'],'networks')
 path=text(o['config_directory'],'config_directory')
 if os.path.normpath(path)!=path or path in {'/srv','/opt','/root'} or not(path.startswith('/srv/') or path.startswith('/opt/') or path.startswith('/root/')):bad('unsafe config directory boundary')
 declared={(x['id'],x['name']) for x in pn+[on]}; volumes={x['name'] for x in vs}; mounted={x['name'] for c in cs for x in c['mounts'] if x['type']=='volume'}
 if mounted!=volumes:bad('declared volumes do not exactly match container mounts')
 for c in cs:
  if not {(x['id'],x['name']) for x in c['networks']}<=declared or not {x['name'] for x in c['mounts'] if x['type']=='volume'}<=volumes:bad('container topology has undeclared objects')
 m.update(volumes=vs,protected_networks=pn,orphan_network=on,config_directory=path,image_ids=set(images));return m
def inspect_c(i,missing=False):
 x=run('inspect','--type','container',i,js=True,missing=missing)
 if x is None:return None
 if type(x) is not list or len(x)!=1:bad('invalid container inspect shape')
 try:
  x=x[0]; labs=x['Config'].get('Labels') or {}; c={'id':x['Id'],'name':x['Name'].removeprefix('/'),'project':labs.get('com.docker.compose.project',''),'service':labs.get('com.docker.compose.service',''),'restart_policy':x['HostConfig']['RestartPolicy']['Name'],'auto_remove':x['HostConfig']['AutoRemove'],'state':x['State']['Status'],'image_id':image_id(x['Image'],'container image'),'mounts':[{'type':z['Type'],'name':z.get('Name',''),'source':z.get('Source',''),'destination':z['Destination'],'rw':z['RW']} for z in x['Mounts']],'networks':[{'name':k,'id':v['NetworkID']} for k,v in x['NetworkSettings']['Networks'].items()]}
 except (KeyError,TypeError):bad('container inspect missing fields')
 if not ID.fullmatch(c['id']) or type(c['auto_remove']) is not bool:bad('invalid container identity')
 return c
def allc():
 ids=[x for x in run('ps','-aq','--no-trunc').splitlines() if x]
 if any(not ID.fullmatch(x) for x in ids) or len(ids)!=len(set(ids)):bad('invalid container inventory')
 return [inspect_c(x) for x in ids]
def inspect_v(n,missing=False):
 x=run('volume','inspect',n,js=True,missing=missing)
 if x is None:return None
 try:x=x[0];l=x.get('Labels') or {};return {'name':x['Name'],'driver':x['Driver'],'scope':x['Scope'],'project':l.get('com.docker.compose.project',''),'compose_volume':l.get('com.docker.compose.volume','')}
 except (KeyError,IndexError,TypeError):bad('invalid volume inspect')
def inspect_n(i,missing=False):
 x=run('network','inspect',i,js=True,missing=missing)
 if x is None:return None
 try:x=x[0];l=x.get('Labels') or {};return {'id':x['Id'],'name':x['Name'],'driver':x['Driver'],'scope':x['Scope'],'internal':x['Internal'],'project':l.get('com.docker.compose.project',''),'compose_network':l.get('com.docker.compose.network',''),'containers':x['Containers']}
 except (KeyError,IndexError,TypeError):bad('invalid network inspect')
def samec(a,e,p):
 return all(a[k]==e[k] for k in ['id','name','project','service']) and ('image_id' not in e or a['image_id']==e['image_id']) and ('auto_remove' not in e or a['auto_remove']==e['auto_remove']) and (not p or (sorted(a['mounts'],key=lambda x:x['destination'])==sorted(e['mounts'],key=lambda x:x['destination']) and sorted(a['networks'],key=lambda x:x['name'])==sorted(e['networks'],key=lambda x:x['name'])))
def projects(m,p):
 ac=allc(); byid={x['id']:x for x in m['containers']};byn={x['name']:x for x in m['containers']}; pro={x['project'] for x in m['containers']}
 if not {x['id'] for x in ac if x['project'] in pro}<={*byid}:bad('project has unapproved container')
 images=set()
 for a in ac:
  if a['name'] in byn and a['id'] not in byid:bad('approved name is a replacement')
  if a['id'] in byid:
   e=byid[a['id']]
   if not samec(a,e,p) or a['restart_policy'] not in {e['restart_policy'],'no'}:bad('container identity, topology, or policy drift')
   images.add(a['image_id'])
 return images
def exclusive(name,ids):
 if any(c['id'] not in ids and any(x['type']=='volume' and x['name']==name for x in c['mounts']) for c in allc()):bad('volume has foreign user')
DIR=os.O_RDONLY|os.O_CLOEXEC|os.O_DIRECTORY|os.O_NOFOLLOW
def mountpoints():
 try:lines=open('/proc/self/mountinfo','rb').read().splitlines()
 except OSError as e:bad('cannot inspect mount boundaries: '+str(e))
 out=set()
 for line in lines:
  f=line.split(b' ')
  if len(f)<6 or b'-' not in f:bad('malformed mount boundary inventory')
  raw=re.sub(rb'\\([0-7]{3})',lambda m:bytes([int(m.group(1),8)]),f[4])
  out.add(os.fsdecode(raw))
 return out
def treecheck(fd,dev):
 for n in os.listdir(fd):
  s=os.stat(n,dir_fd=fd,follow_symlinks=False)
  if stat.S_ISLNK(s.st_mode) or s.st_dev!=dev:bad('config directory crosses safe boundary')
  if stat.S_ISDIR(s.st_mode):
   c=os.open(n,DIR,dir_fd=fd)
   try:
    a=os.fstat(c)
    if (a.st_dev,a.st_ino)!=(s.st_dev,s.st_ino):bad('config directory changed during validation')
    treecheck(c,dev)
   finally:os.close(c)
def boundary(path,targets,keep=False):
 if not os.path.lexists(path):return None if keep else False
 parts=path.strip('/').split('/');mps=mountpoints()
 # Reject the configured root and every nested mountpoint.  st_dev alone does
 # not identify same-filesystem bind mounts.
 if any(x==path or x.startswith(path+'/') for x in mps):bad('config directory contains a mount boundary')
 fd=os.open('/',DIR);dev=os.fstat(fd).st_dev;parent=None;cur=''
 try:
  for i,p in enumerate(parts):
   cur+='/'+p
   n=os.open(p,DIR,dir_fd=fd)
   try:
    s=os.fstat(n)
    if not stat.S_ISDIR(s.st_mode) or s.st_uid or s.st_gid or s.st_mode&0o022:bad('unsafe config directory metadata')
    if s.st_dev!=dev or cur in mps:bad('config directory crosses a mount boundary')
   except:
    os.close(n);raise
   if i==len(parts)-1:parent,fd=fd,n
   else:os.close(fd);fd=n
  treecheck(fd,dev)
  ids={x['id'] for x in targets}
  for c in allc():
   if c['id'] in ids:continue
   for x in c['mounts']:
    q=os.path.normpath(x['source'])
    if x['type']=='bind' and (q==path or q.startswith(path+'/') or path.startswith(q.rstrip('/')+'/')):bad('foreign bind intersects config directory')
  if keep:return parent,fd,parts[-1],dev
  os.close(fd);os.close(parent);return True
 except:
  if parent is not None:
   os.close(fd);os.close(parent)
  else:os.close(fd)
  raise
def prepurge(m):
 present_images=projects(m,True);ids={x['id'] for x in m['containers']}
 if not present_images<=m['image_ids']:bad('container image is not approved')
 if {x['id'] for x in allc()}>=ids and present_images!=m['image_ids']:bad('manifest image set does not match target containers')
 for v in m['volumes']:
  a=inspect_v(v['name'],True)
  if a is not None and a!=v:bad('volume identity drift')
  if a:exclusive(v['name'],ids)
 for n in m['protected_networks']:
  a=inspect_n(n['id']);
  if {k:a[k] for k in n}!=n:bad('protected network drift')
 n=m['orphan_network'];a=inspect_n(n['id'],True)
 if a and ({k:a[k] for k in n}!=n or a['containers']):bad('orphan network drift or endpoints')
 if a is None:
  for i in run('network','ls','-q','--no-trunc').splitlines():
   if inspect_n(i)['name']==n['name']:bad('orphan network name replacement')
 boundary(m['config_directory'],m['containers']);return m['image_ids']
def preservation(m):
 for v in m['volumes']:
  if inspect_v(v['name'],True)!=v:bad('preserved volume is missing or changed')
 for n in m['networks']:
  a=inspect_n(n['id'],True)
  if a is None or {k:a[k] for k in n}!=n:bad('preserved network is missing or changed')
def preremove(m):
 ac=allc();byid={x['id']:x for x in ac};byn={x['name']:x for x in ac}
 for e in m['containers']:
  a=byid.get(e['id'])
  if a is None:bad('requested container is absent before mutation')
  if a['auto_remove']:bad('auto-remove containers cannot be safely stopped while preserving data')
  if byn.get(e['name'],{}).get('id')!=e['id'] or not samec(a,e,True) or a['restart_policy']!=e['restart_policy']:bad('container identity, image, topology, or policy drift')
 preservation(m)
def rec(e,p,missing=False):
 a=inspect_c(e['id'],missing)
 if a is None:
  if any(x['name']==e['name'] for x in allc()):bad('container replaced during execution')
  return None
 if not samec(a,e,p):bad('container changed during execution')
 return a
def stopall(m,p):
 for e in m['containers']:
  a=rec(e,p,p)
  if a and a['restart_policy']!='no':
   if a['restart_policy']!=e['restart_policy']:bad('restart policy changed')
   run('update','--restart=no',e['id']);
   if rec(e,p)['restart_policy']!='no':bad('restart update not applied')
 for e in m['containers']:
  a=rec(e,p,p)
  if a and a['state'] not in {'created','exited'}:run('stop','--time','30',e['id']);a=rec(e,p)
  if a and a['state'] not in {'created','exited'}:bad('container did not stop safely')
def wipe(fd,dev):
 for n in os.listdir(fd):
  s=os.stat(n,dir_fd=fd,follow_symlinks=False)
  if stat.S_ISDIR(s.st_mode):
   c=os.open(n,DIR,dir_fd=fd)
   try:
    a=os.fstat(c)
    if (a.st_dev,a.st_ino)!=(s.st_dev,s.st_ino) or a.st_dev!=dev:bad('config directory changed during deletion')
    wipe(c,dev)
   finally:os.close(c)
   os.rmdir(n,dir_fd=fd)
  else:os.unlink(n,dir_fd=fd)
def rmtree(anchor):
 parent,fd,leaf,dev=anchor
 try:
  wipe(fd,dev);os.close(fd);fd=None
  os.rmdir(leaf,dir_fd=parent)
 finally:
  if fd is not None:os.close(fd)
  os.close(parent)
def purge(m,images):
 stopall(m,True)
 for e in m['containers']:
  a=rec(e,True,True)
  if a:
   if a['state'] not in {'created','exited'} or a['restart_policy']!='no':bad('container not quiesced')
   run('rm',e['id'])
 ids={x['id'] for x in m['containers']}
 for v in m['volumes']:
  a=inspect_v(v['name'],True)
  if a:
   if a!=v:bad('volume changed')
   exclusive(v['name'],ids);run('volume','rm',v['name'])
 n=m['orphan_network'];a=inspect_n(n['id'],True)
 if a:
  if {k:a[k] for k in n}!=n or a['containers']:bad('network changed')
  run('network','rm',n['id'])
 anchor=boundary(m['config_directory'],m['containers'],True)
 if anchor:rmtree(anchor)
 for i in sorted(images-{x['image_id'] for x in allc()}):
  a=run('image','inspect',i,js=True,missing=True)
  if a is not None:
   if len(a)!=1 or image_id(a[0].get('Id'),'image inspect identity')!=i:bad('image identity drift')
   if i not in {x['image_id'] for x in allc()}:run('image','rm',i)
def remove_preserve(m):
 preremove(m)
 stopall(m,True)
 for e in m['containers']:
  a=rec(e,True)
  if a is None or a['state'] not in {'created','exited'} or a['restart_policy']!='no':bad('container not quiesced')
  run('rm',e['id'])
 for e in m['containers']:
  if inspect_c(e['id'],True) is not None:bad('removed container is still present')
  if any(x['name']==e['name'] for x in allc()):bad('removed container name was replaced')
 preservation(m)
def lock():
 fd=os.open('/run/vds-guardian-mutate.lock',os.O_RDWR|os.O_CREAT|os.O_CLOEXEC|os.O_NOFOLLOW,0o600);s=os.fstat(fd)
 if not stat.S_ISREG(s.st_mode) or s.st_uid or s.st_gid or stat.S_IMODE(s.st_mode)!=0o600:bad('unsafe mutation lock')
 try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
 except BlockingIOError:bad('another guardian mutation is already running')
 return fd
def main():
 if len(sys.argv)!=3 or sys.argv[1] not in SLOTS:bad('invalid internal dispatch')
 mode,path=sys.argv[1:];fixed,action=SLOTS[mode]
 if path!=fixed:bad('invalid internal manifest path')
 fd=lock()
 try:
  m=load(mode,path,action);run('info')
  if mode=='purge':purge(m,prepurge(m))
  elif mode=='remove':remove_preserve(m)
  else:projects(m,False);stopall(m,False)
  print('action='+action+' completed')
 finally:os.close(fd)
try:main()
except (Bad,OSError,subprocess.SubprocessError) as e:print('ERROR:',e,file=sys.stderr);sys.exit(1)
PY
}

require_root_and_integrity "$@"

case "$1" in
  audit-compose-projects) audit_compose_projects ;;
  audit-root-storage) audit_root_storage ;;
  audit-storage) audit_storage ;;
  audit-services) audit_services ;;
  audit-security) audit_security ;;
  verify-health) verify_health ;;
  clean-apt-cache) clean_apt_cache ;;
  vacuum-journal-30d) vacuum_journal_30d ;;
  clean-tmpfiles) clean_tmpfiles ;;
  clean-docker-build-cache-30d) clean_docker_build_cache_30d ;;
  purge-approved-compose-project) manifest_mutation purge /etc/vds-guardian/manifests/purge.json ;;
  quiesce-approved-compose-project) manifest_mutation quiesce /etc/vds-guardian/manifests/quiesce.json ;;
  remove-containers-preserve-data) manifest_mutation remove /home/guardian/.vds-guardian/remove-containers.json ;;
  *) fail 'action is not allowlisted' ;;
esac
VDS_GUARDIAN_HELPER

cat >"$tmpdir/new-sudoers" <<'VDS_GUARDIAN_SUDOERS'
# Managed capability boundary for the vds-guardian Hermes profile.
# Every allowed command has fixed arguments; no wildcard or arbitrary path is permitted.
# vds-guardianctl-sha256: dc4a0cdff43ce5d282e399b2d833a985312eb8f92af5b26ced90ebad5ad4a60d
Cmnd_Alias VDS_GUARDIAN_AUDIT = /usr/local/sbin/vds-guardianctl audit-compose-projects, /usr/local/sbin/vds-guardianctl audit-root-storage, /usr/local/sbin/vds-guardianctl audit-storage, /usr/local/sbin/vds-guardianctl audit-services, /usr/local/sbin/vds-guardianctl audit-security, /usr/local/sbin/vds-guardianctl verify-health
Cmnd_Alias VDS_GUARDIAN_CLEAN = /usr/local/sbin/vds-guardianctl clean-apt-cache, /usr/local/sbin/vds-guardianctl vacuum-journal-30d, /usr/local/sbin/vds-guardianctl clean-tmpfiles, /usr/local/sbin/vds-guardianctl clean-docker-build-cache-30d
Cmnd_Alias VDS_GUARDIAN_MANIFEST_MUTATE = /usr/local/sbin/vds-guardianctl purge-approved-compose-project, /usr/local/sbin/vds-guardianctl quiesce-approved-compose-project, /usr/local/sbin/vds-guardianctl remove-containers-preserve-data
guardian ALL=(root) NOPASSWD: VDS_GUARDIAN_AUDIT, VDS_GUARDIAN_CLEAN, VDS_GUARDIAN_MANIFEST_MUTATE
VDS_GUARDIAN_SUDOERS

[[ $(file_sha256 "$tmpdir/new-helper") == "$NEW_HELPER_SHA256" ]] || fail 'embedded helper hash does not match the reviewed build'
[[ $(file_sha256 "$tmpdir/new-sudoers") == "$NEW_SUDOERS_SHA256" ]] || fail 'embedded sudoers hash does not match the reviewed build'
require_helper_authority "$tmpdir/new-helper" "$tmpdir/new-sudoers"
bash -n "$tmpdir/new-helper"
visudo -cf "$tmpdir/new-sudoers"

if [[ ${current_helper_sha256} == "$NEW_HELPER_SHA256" && ${current_sudoers_sha256} == "$NEW_SUDOERS_SHA256" ]]; then
  require_installed_state "$NEW_HELPER_SHA256" "$NEW_SUDOERS_SHA256"
  bash -n "$HELPER_PATH"
  visudo -cf "$SUDOERS_PATH"
  cmp -s "$tmpdir/new-helper" "$HELPER_PATH" || fail 'installed helper is not the exact reviewed new file'
  cmp -s "$tmpdir/new-sudoers" "$SUDOERS_PATH" || fail 'installed sudoers is not the exact reviewed new file'
  printf '%s\n' 'READY: guardian helper and sudoers are already at the reviewed current version'
  committed=1
  exit 0
fi

case "${current_helper_sha256}:${current_sudoers_sha256}" in
  "${BASELINE_V1_HELPER_SHA256}:${BASELINE_V1_SUDOERS_SHA256}")
    selected_baseline_helper_sha256=$BASELINE_V1_HELPER_SHA256
    selected_baseline_sudoers_sha256=$BASELINE_V1_SUDOERS_SHA256
    ;;
  "${BASELINE_V2_HELPER_SHA256}:${BASELINE_V2_SUDOERS_SHA256}")
    selected_baseline_helper_sha256=$BASELINE_V2_HELPER_SHA256
    selected_baseline_sudoers_sha256=$BASELINE_V2_SUDOERS_SHA256
    ;;
  "${BASELINE_V3_HELPER_SHA256}:${BASELINE_V3_SUDOERS_SHA256}")
    selected_baseline_helper_sha256=$BASELINE_V3_HELPER_SHA256
    selected_baseline_sudoers_sha256=$BASELINE_V3_SUDOERS_SHA256
    ;;
  "${BASELINE_V4_HELPER_SHA256}:${BASELINE_V4_SUDOERS_SHA256}")
    selected_baseline_helper_sha256=$BASELINE_V4_HELPER_SHA256
    selected_baseline_sudoers_sha256=$BASELINE_V4_SUDOERS_SHA256
    ;;
  "${BASELINE_V5_HELPER_SHA256}:${BASELINE_V5_SUDOERS_SHA256}")
    selected_baseline_helper_sha256=$BASELINE_V5_HELPER_SHA256
    selected_baseline_sudoers_sha256=$BASELINE_V5_SUDOERS_SHA256
    ;;
  *) fail 'installed helper and sudoers do not match an exact supported baseline pair; no changes made' ;;
esac

# Repeat the complete boundary, leaf metadata, and baseline hash checks directly
# before backup, then prove both private backup copies match that baseline.
require_installed_state "$selected_baseline_helper_sha256" "$selected_baseline_sudoers_sha256"
install -m 600 -o root -g root -- "$HELPER_PATH" "$tmpdir/original-helper"
install -m 600 -o root -g root -- "$SUDOERS_PATH" "$tmpdir/original-sudoers"
[[ $(file_sha256 "$tmpdir/original-helper") == "$selected_baseline_helper_sha256" ]] || fail 'helper changed while preparing backup'
[[ $(file_sha256 "$tmpdir/original-sudoers") == "$selected_baseline_sudoers_sha256" ]] || fail 'sudoers changed while preparing backup'

# Repeat once more immediately before installation. Replacement is staged in
# each verified destination directory and mv -T replaces the leaf itself.
require_installed_state "$selected_baseline_helper_sha256" "$selected_baseline_sudoers_sha256"
mutation_started=1
atomic_replace "$tmpdir/new-helper" "$HELPER_PATH" 0755
atomic_replace "$tmpdir/new-sudoers" "$SUDOERS_PATH" 0440

require_installed_state "$NEW_HELPER_SHA256" "$NEW_SUDOERS_SHA256"
bash -n "$HELPER_PATH"
visudo -cf "$SUDOERS_PATH"
cmp -s "$tmpdir/new-helper" "$HELPER_PATH" || fail 'installed helper is not the exact reviewed new file'
cmp -s "$tmpdir/new-sudoers" "$SUDOERS_PATH" || fail 'installed sudoers is not the exact reviewed new file'

committed=1
printf '%s\n' 'READY: guardian helper and sudoers upgraded from the exact supported baseline'
