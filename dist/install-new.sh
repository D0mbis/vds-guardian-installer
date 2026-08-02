#!/bin/bash
set -Eeuo pipefail
PATH='/usr/sbin:/usr/bin:/sbin:/bin'
umask 077
export LC_ALL=C

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

usage() {
  printf '%s\n' "Usage: sudo bash install-new.sh --public-key 'ssh-ed25519 AAAA...' --enrollment-token-file /protected/path" >&2
  exit 2
}

[[ ${EUID} -eq 0 ]] || fail 'run this installer as root'
[[ $# -eq 4 && $1 == '--public-key' && $3 == '--enrollment-token-file' ]] || usage
public_key=$2
enrollment_token_file=$4
[[ ${public_key} != *$'\n'* && ${public_key} != *$'\r'* ]] || fail 'public key must be exactly one line'
[[ -f ${enrollment_token_file} && ! -L ${enrollment_token_file} ]] || fail 'unsafe enrollment token file'
token_file_metadata=$(stat -c '%u:%a:%F' "$enrollment_token_file")
token_file_owner=${token_file_metadata%%:*}
token_file_rest=${token_file_metadata#*:}
[[ ${token_file_rest} == '600:regular file' ]] || fail 'unsafe enrollment token file metadata'
[[ ${token_file_owner} == 0 || ${token_file_owner} == "${SUDO_UID:-0}" ]] || fail 'unexpected enrollment token file owner'
mapfile -t enrollment_token_lines <"$enrollment_token_file"
[[ ${#enrollment_token_lines[@]} -eq 1 ]] || fail 'invalid enrollment token file'
enrollment_token=${enrollment_token_lines[0]}
[[ ${enrollment_token} =~ ^vg1_[A-Za-z0-9_-]{43}$ ]] || fail 'invalid enrollment token'

for command in adduser userdel install stat visudo bash sudo ssh-keygen getent id mktemp wc rm; do
  command -v "$command" >/dev/null 2>&1 || fail "required command is missing: $command"
done

hostname
id

if getent passwd guardian >/dev/null; then
  fail 'guardian already exists; no changes made'
fi
if [[ -e /home/guardian ]]; then
  fail 'guardian home already exists; no changes made'
fi
if [[ -e /usr/local/sbin/vds-guardianctl || -e /etc/sudoers.d/vds-guardian ]]; then
  fail 'guardian helper or sudoers file already exists; no changes made'
fi

tmpdir=$(mktemp -d)
created_guardian=0
committed=0
cleanup() {
  status=$?
  if [[ $committed -eq 0 && $created_guardian -eq 1 ]]; then
    rm -f /etc/sudoers.d/vds-guardian
    rm -f /usr/local/sbin/vds-guardianctl
    userdel -r guardian >/dev/null 2>&1 || true
  fi
  rm -rf "$tmpdir"
  trap - EXIT
  exit "$status"
}
trap cleanup EXIT

cat >"$tmpdir/vds-guardianctl" <<'VDS_GUARDIAN_HELPER'
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
SLOTS={'purge':('/etc/vds-guardian/manifests/purge.json','purge-approved-compose-project'),'quiesce':('/etc/vds-guardian/manifests/quiesce.json','quiesce-approved-compose-project')}
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
def container(o,w,purge):
 want={'id','name','project','service','restart_policy'}|({'mounts','networks'} if purge else set());keys(o,want,w)
 c={k:text(o[k],w+'.'+k,ID if k=='id' else NAME if k in {'name','project','service'} else None) for k in ['id','name','project','service','restart_policy']}
 if c['restart_policy'] not in {'no','always','on-failure','unless-stopped'}:bad(w+' restart policy invalid')
 if purge:
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
 try:o=json.loads(manifest_bytes(path).decode(),object_pairs_hook=pairs,parse_constant=lambda x:bad('invalid JSON number'))
 except (ValueError,UnicodeError,OSError) as e:bad('malformed or unsafe manifest: '+str(e))
 extra={'volumes','orphan_network','protected_networks','config_directory','image_ids'} if mode=='purge' else set();keys(o,{'schema','action','containers'}|extra,'manifest')
 if type(o['schema']) is not int or o['schema']!=1 or o['action']!=action:bad('wrong manifest schema or action')
 if type(o['containers']) is not list or not 1<=len(o['containers'])<=128:bad('invalid container count')
 cs=[container(x,'containers[%d]'%i,mode=='purge') for i,x in enumerate(o['containers'])];uniq(cs,lambda x:x['id'],'containers');uniq(cs,lambda x:x['name'],'containers');m={'containers':cs}
 if mode!='purge':return m
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
  x=x[0]; labs=x['Config'].get('Labels') or {}; c={'id':x['Id'],'name':x['Name'].removeprefix('/'),'project':labs.get('com.docker.compose.project',''),'service':labs.get('com.docker.compose.service',''),'restart_policy':x['HostConfig']['RestartPolicy']['Name'],'state':x['State']['Status'],'image_id':image_id(x['Image'],'container image'),'mounts':[{'type':z['Type'],'name':z.get('Name',''),'source':z.get('Source',''),'destination':z['Destination'],'rw':z['RW']} for z in x['Mounts']],'networks':[{'name':k,'id':v['NetworkID']} for k,v in x['NetworkSettings']['Networks'].items()]}
 except (KeyError,TypeError):bad('container inspect missing fields')
 if not ID.fullmatch(c['id']):bad('abbreviated Docker identity')
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
 return all(a[k]==e[k] for k in ['id','name','project','service']) and (not p or (sorted(a['mounts'],key=lambda x:x['destination'])==sorted(e['mounts'],key=lambda x:x['destination']) and sorted(a['networks'],key=lambda x:x['name'])==sorted(e['networks'],key=lambda x:x['name'])))
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
  *) fail 'action is not allowlisted' ;;
esac
VDS_GUARDIAN_HELPER

cat >"$tmpdir/vds-guardian.sudoers" <<'VDS_GUARDIAN_SUDOERS'
# Managed capability boundary for the vds-guardian Hermes profile.
# Every allowed command has fixed arguments; no wildcard or arbitrary path is permitted.
Cmnd_Alias VDS_GUARDIAN_AUDIT = /usr/local/sbin/vds-guardianctl audit-compose-projects, /usr/local/sbin/vds-guardianctl audit-storage, /usr/local/sbin/vds-guardianctl audit-services, /usr/local/sbin/vds-guardianctl audit-security, /usr/local/sbin/vds-guardianctl verify-health
Cmnd_Alias VDS_GUARDIAN_CLEAN = /usr/local/sbin/vds-guardianctl clean-apt-cache, /usr/local/sbin/vds-guardianctl vacuum-journal-30d, /usr/local/sbin/vds-guardianctl clean-tmpfiles, /usr/local/sbin/vds-guardianctl clean-docker-build-cache-30d
Cmnd_Alias VDS_GUARDIAN_MANIFEST_MUTATE = /usr/local/sbin/vds-guardianctl purge-approved-compose-project, /usr/local/sbin/vds-guardianctl quiesce-approved-compose-project
guardian ALL=(root) NOPASSWD: VDS_GUARDIAN_AUDIT, VDS_GUARDIAN_CLEAN, VDS_GUARDIAN_MANIFEST_MUTATE
VDS_GUARDIAN_SUDOERS

printf '%s\n' "$public_key" >"$tmpdir/authorized_key"
[[ $(wc -l <"$tmpdir/authorized_key") -eq 1 ]] || fail 'public key must be exactly one line'
ssh-keygen -l -f "$tmpdir/authorized_key" >/dev/null 2>&1 || fail 'invalid SSH public key'
printf '%s\n' "$enrollment_token" >"$tmpdir/enrollment_token"
[[ $(wc -l <"$tmpdir/enrollment_token") -eq 1 ]] || fail 'invalid enrollment token'
bash -n "$tmpdir/vds-guardianctl"
visudo -cf "$tmpdir/vds-guardian.sudoers"

created_guardian=1
adduser --disabled-password --gecos '' guardian
guardian_groups=$(id -nG guardian) || fail 'cannot determine guardian groups'
[[ -n ${guardian_groups} ]] || fail 'guardian group list is empty'
for group in $guardian_groups; do
  case "$group" in
    guardian|users) ;;
    *)
      fail "adduser assigned an unexpected supplemental group: $group; newly created account was removed"
      ;;
  esac
done
install -d -m 700 -o guardian -g guardian /home/guardian/.ssh
install -m 600 -o guardian -g guardian "$tmpdir/authorized_key" /home/guardian/.ssh/authorized_keys
install -m 600 -o guardian -g guardian "$tmpdir/enrollment_token" /home/guardian/.vds-guardian-enrollment
install -m 755 -o root -g root "$tmpdir/vds-guardianctl" /usr/local/sbin/vds-guardianctl
install -m 440 -o root -g root "$tmpdir/vds-guardian.sudoers" /etc/sudoers.d/vds-guardian
visudo -cf /etc/sudoers.d/vds-guardian
stat -c '%U:%G %a %n' /home/guardian/.ssh /home/guardian/.ssh/authorized_keys /home/guardian/.vds-guardian-enrollment /usr/local/sbin/vds-guardianctl /etc/sudoers.d/vds-guardian
id guardian
sudo -u guardian sudo -n -l
committed=1
printf '%s\n' 'READY: guardian and the fixed least-privilege maintenance helper are installed'
