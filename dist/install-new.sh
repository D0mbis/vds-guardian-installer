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
      docker inspect --type container --format 'id={{printf "%q" .Id}} name={{printf "%q" .Name}} image={{printf "%q" .Config.Image}} state={{printf "%q" .State.Status}} restart_policy={{printf "%q" .HostConfig.RestartPolicy.Name}}
compose_project={{printf "%q" (index .Config.Labels "com.docker.compose.project")}} compose_service={{printf "%q" (index .Config.Labels "com.docker.compose.service")}} compose_working_dir={{printf "%q" (index .Config.Labels "com.docker.compose.project.working_dir")}} compose_config_files={{printf "%q" (index .Config.Labels "com.docker.compose.project.config_files")}} compose_oneoff={{printf "%q" (index .Config.Labels "com.docker.compose.oneoff")}} compose_version={{printf "%q" (index .Config.Labels "com.docker.compose.version")}}
{{range .Mounts}}mount type={{printf "%q" .Type}} name={{printf "%q" .Name}} source={{printf "%q" .Source}} destination={{printf "%q" .Destination}} rw={{.RW}}
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
  *) fail 'action is not allowlisted' ;;
esac
VDS_GUARDIAN_HELPER

cat >"$tmpdir/vds-guardian.sudoers" <<'VDS_GUARDIAN_SUDOERS'
# Managed capability boundary for the vds-guardian Hermes profile.
# Every allowed command has fixed arguments; no wildcard or arbitrary path is permitted.
Cmnd_Alias VDS_GUARDIAN_AUDIT = /usr/local/sbin/vds-guardianctl audit-compose-projects, /usr/local/sbin/vds-guardianctl audit-storage, /usr/local/sbin/vds-guardianctl audit-services, /usr/local/sbin/vds-guardianctl audit-security, /usr/local/sbin/vds-guardianctl verify-health
Cmnd_Alias VDS_GUARDIAN_CLEAN = /usr/local/sbin/vds-guardianctl clean-apt-cache, /usr/local/sbin/vds-guardianctl vacuum-journal-30d, /usr/local/sbin/vds-guardianctl clean-tmpfiles, /usr/local/sbin/vds-guardianctl clean-docker-build-cache-30d
guardian ALL=(root) NOPASSWD: VDS_GUARDIAN_AUDIT, VDS_GUARDIAN_CLEAN
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
