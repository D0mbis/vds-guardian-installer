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
readonly NEW_HELPER_SHA256='699c1c32b3397cd43302fe3a1a14ec3360e7f95427df8452f8735e61b182117d'
readonly NEW_SUDOERS_SHA256='3580b0d94eb24be1d5a18cab2e6bc40e83c7ec1c09c8fc552f97c595ab131341'

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

[[ ${EUID} -eq 0 ]] || fail 'run this upgrade as root (for example: sudo bash upgrade-existing.sh)'
[[ $# -eq 0 ]] || fail 'this upgrade accepts no arguments'

for command in bash cat cmp flock getent id install mktemp mv rm sha256sum stat visudo; do
  command -v "$command" >/dev/null 2>&1 || fail "required command is missing: $command"
done

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
      docker inspect --type container --format 'id={{printf "%q" .Id}} name={{printf "%q" .Name}} image={{printf "%q" .Config.Image}} state={{printf "%q" .State.Status}} restart_policy={{printf "%q" .HostConfig.RestartPolicy.Name}}
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

cat >"$tmpdir/new-sudoers" <<'VDS_GUARDIAN_SUDOERS'
# Managed capability boundary for the vds-guardian Hermes profile.
# Every allowed command has fixed arguments; no wildcard or arbitrary path is permitted.
Cmnd_Alias VDS_GUARDIAN_AUDIT = /usr/local/sbin/vds-guardianctl audit-compose-projects, /usr/local/sbin/vds-guardianctl audit-storage, /usr/local/sbin/vds-guardianctl audit-services, /usr/local/sbin/vds-guardianctl audit-security, /usr/local/sbin/vds-guardianctl verify-health
Cmnd_Alias VDS_GUARDIAN_CLEAN = /usr/local/sbin/vds-guardianctl clean-apt-cache, /usr/local/sbin/vds-guardianctl vacuum-journal-30d, /usr/local/sbin/vds-guardianctl clean-tmpfiles, /usr/local/sbin/vds-guardianctl clean-docker-build-cache-30d
guardian ALL=(root) NOPASSWD: VDS_GUARDIAN_AUDIT, VDS_GUARDIAN_CLEAN
VDS_GUARDIAN_SUDOERS

[[ $(file_sha256 "$tmpdir/new-helper") == "$NEW_HELPER_SHA256" ]] || fail 'embedded helper hash does not match the reviewed build'
[[ $(file_sha256 "$tmpdir/new-sudoers") == "$NEW_SUDOERS_SHA256" ]] || fail 'embedded sudoers hash does not match the reviewed build'
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
