# VDS Guardian Installer

Generic, auditable least-privilege installer for the Hermes `vds-guardian` profile on Ubuntu/Debian VDS hosts.

## What it installs

- unprivileged Unix user `guardian` for new hosts;
- root-owned `/usr/local/sbin/vds-guardianctl` (`0755`);
- exact `/etc/sudoers.d/vds-guardian` allowlist (`0440`);
- no password, no membership in `sudo`, `docker`, `adm`, or `systemd-journal`;
- no `NOPASSWD: ALL`, wildcard, arbitrary path, shell, editor, general package-manager, general `systemctl`, or unrestricted Docker access.

## Fixed actions

Read-only:

- `audit-compose-projects` — fail-closed Docker inventory of containers, volumes, networks, and selected Compose metadata; it does not read environment/configuration file contents or volume contents;
- `audit-storage`
- `audit-services`
- `audit-security`
- `verify-health`

Mutating and intended to require a separate Hermes approval:

- `clean-apt-cache`
- `vacuum-journal-30d`
- `clean-tmpfiles`
- `clean-docker-build-cache-30d`
- `purge-approved-compose-project` — permanently removes only objects proven against the fixed `/etc/vds-guardian/manifests/purge.json`;
- `quiesce-approved-compose-project` — sets restart policy `no` and stops only containers proven against `/etc/vds-guardian/manifests/quiesce.json`;
- `remove-containers-preserve-data` — reads the fixed guardian-owned `/home/guardian/.vds-guardian/remove-containers.json`, re-proves the selected containers, sets restart policy `no`, stops them safely, and removes them by full ID without `-v`.

The two manifest actions accept no arguments. Each slot requires strict JSON
schema version `1`, the matching action name, full 64-character Docker IDs,
explicit container/project/service/policy identity, and no duplicate or unknown
keys. Purge additionally declares exact image IDs, mount and network sets, volume identity,
one endpoint-free orphan network, protected networks, and a normalized
root-owned physical configuration directory below `/srv`, `/opt`, or `/root`. Manifest
files must be non-symlink regular files owned by `root:root`, mode `0400`, below
non-writable root-owned physical parents. The helper fails before mutation on
metadata, identity, topology, sharing, endpoint, policy, or directory drift.

The removal request is also schema `1` and accepts no arguments or unknown or
duplicate JSON keys. Each selected container declares its full ID, exact name,
Compose project/service, image ID, restart policy, exact boolean `auto_remove`
identity, complete mount topology, and complete network ID/name topology. The
only accepted value for removal targets is `false`: containers created with
`docker run --rm` are rejected before any mutation because stopping one may
automatically delete its anonymous volumes. Top-level `volumes` and `networks`
declare the exact preservation set, including anonymous volume names and Docker/Compose
identity metadata. The request directory must be a real `guardian:guardian`
`0700` directory and the request a real `guardian:guardian` `0600` regular file;
`/`, `/home`, and the guardian home are validated component-by-component and
the file is opened with no-follow, descriptor-based checks. After removal the
helper proves every target ID absent and every declared volume and network still
present with the same identity. It never invokes volume, network, image, bind,
configuration-directory, container creation, or container exec deletion APIs.
A request may select a subset of a Compose project; unselected containers are
not mutated. A partial Docker failure is reported and left visible for review.

To prepare the fixed request slot as `guardian`, create
`/home/guardian/.vds-guardian` with mode `0700`, write the complete request
atomically inside it, and set the request mode to `0600` before invoking the
fixed action.

The OS allowlist limits the possible mutations, while Hermes policy supplies the human approval gate. Anyone who obtains the `guardian` SSH key can invoke these fixed actions, so protect and rotate that key.

## Installers

- `dist/install-new.sh`: creates a new `guardian` account, accepts one public SSH key through `--public-key`, and reads a short-lived one-time proof from a protected file supplied through `--enrollment-token-file`. The token value never appears in the installer's process arguments. The proof lets Hermes verify first contact without asking the user to compare SSH fingerprints and is removed after successful enrollment.
- `dist/install-existing.sh`: upgrades an existing unprivileged `guardian` account that has no sudo commands.
- `dist/upgrade-existing.sh`: fail-closed, no-argument root upgrade for hosts that have one of the exact previously published helper/sudoers pairs supported by the artifact, including the exact deployed `16db836` eleven-action helper/sudoers pair. It validates the fixed parent/leaf ownership boundary, serializes its own runs with a fail-fast lock under `/run`, rejects metadata or content drift, stages fixed-path replacements, and verifies rollback of both files. It is idempotent only for the exact current files and does not change SSH, accounts, groups, Docker, services, or firewall state. The lock serializes this upgrader in the ordinary local administrative model; it is not a claim of protection from a malicious concurrent root process.

Use an immutable commit URL and verify `SHA256SUMS` before root execution. Concrete pinned commands are intentionally generated by the Hermes profile after publication so they cannot silently follow a moving branch.

## Development

```bash
python3 tools/build.py
bash -n dist/install-new.sh
bash -n dist/install-existing.sh
bash -n dist/upgrade-existing.sh
visudo -cf src/vds-guardian.sudoers
```

The generated `dist/` files must match the reviewed `src/` and `templates/` inputs.

## Scope

The helper is generic. It does not contain IP addresses, domains, SSH private keys, tokens, container names, or application-specific cleanup rules. Application-specific cleanup must be added as a separately reviewed fixed action rather than arbitrary root shell access.
