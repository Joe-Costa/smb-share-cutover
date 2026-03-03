# SMB Share Cutover Tool for Qumulo

<!-- version-badge:start -->
**Version: 1.2.1**
<!-- version-badge:end -->

Safely disable or remove individual SMB shares from a Qumulo cluster without
disrupting sessions on other shares. The underlying filesystem is never touched.

## Requirements

- Python 3.6+
- Qumulo Core 7.x
- No external dependencies (stdlib only)
- Optional: `qq` CLI (`pip install qumulo_api`)

## Authentication

The tool reads a bearer token from a JSON credentials file (default: `~/.qfsd_cred`).
If you have the `qq` CLI installed you can generate one with:

```
qq login -h <cluster>
```

Or specify a custom path with `--creds-file`.

## RBAC Privileges

The minimum set of privileges required to run this tool:

| Privilege | Risk | Used For |
|-----------|------|----------|
| `PRIVILEGE_SMB_SHARE_READ` | 0 | List and inspect shares |
| `PRIVILEGE_SMB_SESSION_READ` | 0 | List active sessions |
| `PRIVILEGE_SMB_FILE_HANDLE_READ` | 0 | List open file handles |
| `PRIVILEGE_FS_ATTRIBUTES_READ` | 0 | Resolve share paths to file IDs |
| `PRIVILEGE_SMB_SETTINGS_READ` | 0 | Check hide-from-unauthorized-hosts setting |
| `PRIVILEGE_SMB_FILE_HANDLE_WRITE` | 1 | Close file handles on target share |
| `PRIVILEGE_SMB_SHARE_WRITE` | 2 | Lockout, delete, and restore shares |
| `PRIVILEGE_SMB_SETTINGS_WRITE` | 2 | Enable hide-from-unauthorized-hosts |

## Helpful Qumulo Care Articles:

[How to get an Access Token](https://docs.qumulo.com/administrator-guide/connecting-to-external-services/creating-using-access-tokens-to-authenticate-external-services-qumulo-core.html) 

[Qumulo Role Based Access Control](https://care.qumulo.com/hc/en-us/articles/360036591633-Role-Based-Access-Control-RBAC-with-Qumulo-Core#managing-roles-by-using-the-web-ui-0-7)


## Commands

### list-shares

Show all SMB shares with active session counts and disabled status.

```
python3 smb_share_cutover.py --host <cluster> list-shares
```

```
┌────┬────────────┬─────────────┬────────┬──────────┬──────────┐
│ ID │ Share Name │ Path        │ Tenant │ Sessions │ Disabled │
├────┼────────────┼─────────────┼────────┼──────────┼──────────┤
│ 3  │ Projects   │ /projects   │ 1      │ 5        │          │
│ 7  │ Archive    │ /archive    │ 1      │ 0        │ Yes      │
└────┴────────────┴─────────────┴────────┴──────────┴──────────┘
```

A share shows `Disabled: Yes` when it has a DENY 0.0.0.0/0 network rule applied.

### list-share

Show detailed session information for a specific share.

```
python3 smb_share_cutover.py --host <cluster> list-share --id 3
```

```
┌──────────────────┬───────────────┬───────────────┬─────────────────┬────────────┬───────────┬───────────┬───────┐
│ User             │ Source IP     │ Server IP     │ Shares Accessed │ Open Files │ Idle Time │ Encrypted │ Guest │
├──────────────────┼───────────────┼───────────────┼─────────────────┼────────────┼───────────┼───────────┼───────┤
│ DOMAIN\jsmith    │ 10.0.1.50     │ 10.0.0.10     │ Projects, Home  │ 12         │ ~30s      │ No        │ No    │
└──────────────────┴───────────────┴───────────────┴─────────────────┴────────────┴───────────┴───────────┴───────┘
```

### disable

Block all access to a share without deleting it. The share stays in the
configuration but becomes inaccessible.

```
python3 smb_share_cutover.py --host <cluster> disable --id 3
python3 smb_share_cutover.py --host <cluster> disable --id 3 --dry-run
```

What it does:
1. Backs up the share configuration to `backups/`
2. Sets a DENY 0.0.0.0/0 network rule (blocks all clients immediately)
3. Enables `hide_shares_from_unauthorized_hosts` in SMB settings (if not already on)
4. Closes all open file handles on the share

Sessions connected to other shares are not affected.

### enable

Re-enable a previously disabled share by restoring its original network
permissions from a backup file.

```
python3 smb_share_cutover.py --host <cluster> enable --id 3 --backup backups/Archive_20260213_091504.json
python3 smb_share_cutover.py --host <cluster> enable --id 3 --backup backups/Archive_20260213_091504.json --dry-run
```

What it does:
1. Reads the original `network_permissions` from the backup JSON
2. Verifies the share exists and is currently disabled (DENY 0.0.0.0/0 rule present)
3. PATCHes the share's `network_permissions` back to the original values

This is the inverse of `disable`. Use it when you disabled a share and want to
bring it back without deleting and recreating it. If you used `remove` instead
of `disable`, use `restore` to recreate the share.

### remove

Fully remove a share: disable it first, then delete the share definition.

```
python3 smb_share_cutover.py --host <cluster> remove --share ShareName
python3 smb_share_cutover.py --host <cluster> remove --share ShareName --dry-run
```

What it does:
1. Backs up the share configuration to `backups/`
2. Applies network lockout (same as `disable`)
3. Closes all open file handles on the share
4. Deletes the share
5. Verifies: share gone, filesystem intact, other sessions alive

The filesystem directory and its contents are never deleted.

### restore

Recreate a previously removed or disabled share from its backup file.

```
python3 smb_share_cutover.py --host <cluster> restore --backup backups/ShareName_20260213_091504.json
python3 smb_share_cutover.py --host <cluster> restore --backup backups/ShareName_20260213_091504.json --dry-run
```

The share is recreated with its original permissions, network rules, and settings.
Restore will refuse to run if a share with the same name already exists.
If the share exists but is disabled, the error message will suggest using
`enable` instead.

### enable vs restore

| Scenario | Share still exists? | Command | What it does |
|----------|---------------------|---------|--------------|
| Used `disable` | Yes (locked out) | `enable` | PATCHes network permissions back to original |
| Used `remove` | No (deleted) | `restore` | Creates a new share from the backup JSON |

Use `enable` after `disable`, and `restore` after `remove`.

## Global Options

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--host` | Yes | — | Qumulo cluster hostname or IP |
| `--creds-file` | No | `~/.qfsd_cred` | Path to credentials JSON file |

## Backups

Every `disable` and `remove` operation saves the full share configuration to
`backups/<ShareName>_<YYYYMMDD_HHMMSS>.json` before making changes.
Any `$` characters in the share name are replaced with `_` in the backup
filename to avoid shell expansion issues.
These files contain everything needed to recreate the share: permissions,
network rules, ABE, encryption, file/directory modes, and tenant assignment.



## How It Works

Deleting an SMB share while clients are connected is not clean — SMB session
caching allows clients to continue operating on a deleted share until the
cached tree connect expires. This tool solves that by applying a network-level
DENY rule before deletion, which the Qumulo SMB server enforces immediately
on all I/O, regardless of session cache state.

**IMPORTANT NOTE** The client will not receive any notification that the SMB share has been disabled and the client might have local
cached access to files it has already opened until the SMB timeout period expires.  This timeout value varies by client implementation but is
in the range of 30 to 60 seconds.

The sequence:
1. **Backup** — save the share config so it can be restored
2. **Network lockout** — DENY 0.0.0.0/0 blocks all clients instantly
3. **Hide share** — ensure the global SMB setting hides denied shares from UNC enumeration
4. **Close handles** — release any remaining file handles on the target share only
5. **Delete** (remove only) — remove the share definition from the cluster

Only file handles on the target share are closed. Other shares and their
sessions are left untouched.

The `disable` / `enable` pairing lets you temporarily take a share offline and
bring it back without deleting and recreating it. The `remove` / `restore`
pairing is for permanent removal with the option to recreate from backup.
