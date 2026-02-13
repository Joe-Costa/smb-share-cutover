#!/usr/bin/env python3
"""
SMB Share Cutover Tool for Qumulo Clusters

Safely removes an SMB share by:
  1. Backing up the full share configuration to JSON
  2. Denying all network access (forces immediate client disconnection)
  3. Closing remaining file handles on the target share
  4. Deleting the share

The underlying filesystem is never touched.
A restore function can recreate the share from the backup.

Usage:
    # List all shares with session counts
    python3 smb_share_cutover.py --host <cluster> list-shares

    # Show detailed sessions for a specific share
    python3 smb_share_cutover.py --host <cluster> list-share --id <share-id>

    # Disable a share (lockout + close handles, no delete)
    python3 smb_share_cutover.py --host <cluster> disable --id <share-id>

    # Remove a share (backup + lockout + close handles + delete)
    python3 smb_share_cutover.py --host <cluster> remove --share <share-name>

    # Restore a share from backup
    python3 smb_share_cutover.py --host <cluster> restore --backup backups/<share-name>_<timestamp>.json

    # Dry-run (show what would happen without making changes)
    python3 smb_share_cutover.py --host <cluster> remove --share <share-name> --dry-run
"""

import argparse
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

DEFAULT_CREDS = str(Path.home() / ".qfsd_cred")
PORT = 8000
BACKUP_DIR = Path(__file__).parent / "backups"

# Deny-all network rule: blocks every IP from every right
DENY_ALL_NETWORK = [
    {
        "type": "DENIED",
        "address_ranges": ["0.0.0.0/0"],
        "rights": ["READ", "WRITE", "CHANGE_PERMISSIONS"],
    }
]

# Initialized in main() from CLI args
BASE_URL = None
TOKEN = None
SSL_CTX = None


def init_connection(host, creds_file):
    """Set up module globals from CLI arguments."""
    global BASE_URL, TOKEN, SSL_CTX

    BASE_URL = f"https://{host}:{PORT}"

    SSL_CTX = ssl.create_default_context()
    SSL_CTX.check_hostname = False
    SSL_CTX.verify_mode = ssl.CERT_NONE

    creds_path = Path(creds_file).expanduser()
    if not creds_path.exists():
        print(f"ERROR: Credentials file not found: {creds_path}", file=sys.stderr)
        sys.exit(1)
    with open(creds_path) as f:
        TOKEN = json.load(f)["bearer_token"]


# ── Table rendering ──────────────────────────────────────────────────────────

def render_table(headers, rows):
    """Render a Unicode box-drawing table. Returns a string."""
    # Calculate column widths (minimum = header width)
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))

    def hline(left, mid, right, fill="─"):
        return left + mid.join(fill * (w + 2) for w in widths) + right

    def data_row(cells):
        parts = []
        for i, cell in enumerate(cells):
            parts.append(f" {str(cell).ljust(widths[i])} ")
        return "│" + "│".join(parts) + "│"

    lines = []
    lines.append(hline("┌", "┬", "┐"))
    lines.append(data_row(headers))
    lines.append(hline("├", "┼", "┤"))
    for row in rows:
        lines.append(data_row(row))
    lines.append(hline("└", "┴", "┘"))
    return "\n".join(lines)


def format_nanoseconds(ns_str):
    """Convert a nanoseconds string to a human-friendly duration."""
    ns = int(ns_str)
    seconds = ns // 1_000_000_000
    if seconds < 60:
        return f"~{seconds}s"
    elif seconds < 3600:
        return f"~{seconds // 60}m"
    elif seconds < 86400:
        hours = seconds // 3600
        mins = (seconds % 3600) // 60
        return f"~{hours}h{mins}m"
    else:
        days = seconds // 86400
        hours = (seconds % 86400) // 3600
        return f"~{days}d{hours}h"


# ── API helper ───────────────────────────────────────────────────────────────

def api(method, path, body=None):
    """Make an API call to the Qumulo cluster. Returns parsed JSON or status dict."""
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(url, method=method)
    req.add_header("Authorization", f"Bearer {TOKEN}")
    req.add_header("Content-Type", "application/json")
    req.add_header("accept", "application/json")
    if body is not None:
        req.data = json.dumps(body).encode()

    with urllib.request.urlopen(req, context=SSL_CTX) as resp:
        raw = resp.read()
        if not raw:
            return {"_status": resp.status}
        return json.loads(raw)


# ── Share lookup ─────────────────────────────────────────────────────────────

def get_all_shares():
    """Return a list of all SMB share dicts."""
    shares = api("GET", "/v3/smb/shares/")
    return shares if isinstance(shares, list) else shares.get("entries", [])


def get_share_by_name(share_name):
    """Find an SMB share by name. Returns the share dict or None."""
    for s in get_all_shares():
        if s["share_name"] == share_name:
            return s
    return None


def get_share_by_id(share_id):
    """Fetch a specific SMB share by ID. Returns the share dict."""
    return api("GET", f"/v3/smb/shares/{share_id}")


def get_all_sessions():
    """Return a list of all active SMB session dicts."""
    result = api("GET", "/v1/smb/sessions/")
    return result.get("session_infos", [])


# ── List shares ─────────────────────────────────────────────────────────────

def is_share_disabled(share):
    """Check if a share has a DENY 0.0.0.0/0 network rule (lockout applied)."""
    for rule in share.get("network_permissions", []):
        if rule.get("type") == "DENIED" and "0.0.0.0/0" in rule.get("address_ranges", []):
            return True
    return False


def list_all_shares():
    """Print a table of all SMB shares with their active session counts."""
    shares = get_all_shares()
    sessions = get_all_sessions()

    # Count sessions per share name
    session_counts = {}
    for s in sessions:
        for name in s.get("share_names", []):
            session_counts[name] = session_counts.get(name, 0) + 1

    headers = ["ID", "Share Name", "Path", "Tenant", "Sessions", "Disabled"]
    rows = []
    for share in shares:
        name = share["share_name"]
        rows.append([
            share["id"],
            name,
            share["fs_path"],
            share.get("tenant_id", "?"),
            session_counts.get(name, 0),
            "Yes" if is_share_disabled(share) else "",
        ])

    print(f"\nSMB Shares ({len(shares)} total)\n")
    print(render_table(headers, rows))


def list_share(share_id):
    """Print detailed session info for a specific share in a formatted table."""
    try:
        share = get_share_by_id(share_id)
    except urllib.error.HTTPError as e:
        print(f"ERROR: Share ID {share_id} not found (HTTP {e.code})", file=sys.stderr)
        sys.exit(1)

    share_name = share["share_name"]
    sessions = get_all_sessions()

    # Filter sessions that include this share
    matching = [s for s in sessions if share_name in s.get("share_names", [])]

    print(f"\nShare: {share_name} (id={share['id']}, path={share['fs_path']}, tenant={share.get('tenant_id', '?')})")
    print(f"\nActive SMB Sessions ({len(matching)} session{'s' if len(matching) != 1 else ''})\n")

    if not matching:
        print("  No active sessions on this share.")
        return

    headers = ["User", "Source IP", "Server IP", "Shares Accessed", "Open Files", "Idle Time", "Encrypted", "Guest"]
    rows = []
    for s in matching:
        user = s["user"].get("name") or s["user"].get("sid", "unknown")
        idle = format_nanoseconds(s["time_idle"]["nanoseconds"])
        shares_str = ", ".join(s.get("share_names", []))
        rows.append([
            user,
            s.get("originator", "?"),
            s.get("server_address", "?"),
            shares_str,
            s.get("num_opens", 0),
            idle,
            "Yes" if s.get("is_encrypted") else "No",
            "Yes" if s.get("is_guest") else "No",
        ])

    print(render_table(headers, rows))


# ── Disable share ───────────────────────────────────────────────────────────

def disable_share(share_id, dry_run=False):
    """Disable a share by applying network lockout and closing handles.
    The share remains in the configuration but is inaccessible.
    A backup is saved before any changes."""
    try:
        share = get_share_by_id(share_id)
    except urllib.error.HTTPError as e:
        print(f"ERROR: Share ID {share_id} not found (HTTP {e.code})", file=sys.stderr)
        sys.exit(1)

    share_name = share["share_name"]
    fs_path = share["fs_path"]

    print(f"{'[DRY-RUN] ' if dry_run else ''}Disabling share: {share_name} (id={share_id})\n")

    # Step 1: Backup
    print("Step 1: Backup share configuration")
    backup_file = backup_share(share, dry_run=dry_run)
    print()

    # Step 2: Network lockout
    print("Step 2: Apply network lockout (deny all hosts)")
    lockout_share(share_id, dry_run=dry_run)
    if not dry_run:
        time.sleep(2)
    print()

    # Step 3: Close file handles
    print("Step 3: Close file handles")
    close_share_handles(fs_path, dry_run=dry_run)
    print()

    if not dry_run:
        print(f"Share '{share_name}' is now disabled (network denied, handles closed)")
        print(f"The share still exists but no clients can access it.")
    else:
        print(f"[DRY-RUN] Would disable share '{share_name}'")

    print(f"\nBackup: {backup_file}")
    print(f"Restore with: python3 {__file__} restore --backup {backup_file}")


# ── Backup ───────────────────────────────────────────────────────────────────

def backup_share(share, dry_run=False):
    """Save the full share configuration to a timestamped JSON file."""
    BACKUP_DIR.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = BACKUP_DIR / f"{share['share_name']}_{ts}.json"

    if dry_run:
        print(f"  [DRY-RUN] Would back up share config to {filename}")
        return filename

    with open(filename, "w") as f:
        json.dump(share, f, indent=2)
    print(f"  Backup saved: {filename}")
    return filename


# ── Network lockout ──────────────────────────────────────────────────────────

def ensure_hide_shares_from_unauthorized_hosts(dry_run=False):
    """Ensure the global SMB setting to hide shares from unauthorized hosts
    is enabled. This prevents locked-out shares from appearing in UNC
    enumeration (e.g. \\\\server when browsing from a denied host)."""
    settings = api("GET", "/v1/smb/settings")
    if settings.get("hide_shares_from_unauthorized_hosts"):
        print("  hide_shares_from_unauthorized_hosts: already enabled")
        return

    if dry_run:
        print("  [DRY-RUN] Would enable hide_shares_from_unauthorized_hosts")
        return

    api("PATCH", "/v1/smb/settings", {
        "hide_shares_from_unauthorized_hosts": True,
    })
    print("  hide_shares_from_unauthorized_hosts: enabled")


def lockout_share(share_id, dry_run=False):
    """PATCH network_permissions to deny all hosts. This immediately blocks
    any new I/O from connected clients, even with cached SMB sessions.
    Also ensures the global SMB hide-from-unauthorized-hosts setting is on
    so the share disappears from UNC enumeration."""
    if dry_run:
        print(f"  [DRY-RUN] Would PATCH share {share_id} network_permissions → DENY 0.0.0.0/0")
        ensure_hide_shares_from_unauthorized_hosts(dry_run=True)
        return

    api("PATCH", f"/v3/smb/shares/{share_id}", {
        "network_permissions": DENY_ALL_NETWORK,
    })
    print(f"  Network lockout applied (share {share_id}): all hosts denied")
    ensure_hide_shares_from_unauthorized_hosts()


# ── Close file handles ───────────────────────────────────────────────────────

def get_file_id_for_path(fs_path):
    """Resolve an fs_path to its file_number/id."""
    encoded = urllib.parse.quote(fs_path, safe="")
    attrs = api("GET", f"/v1/files/{encoded}/info/attributes")
    return attrs["file_number"]


def close_share_handles(fs_path, dry_run=False):
    """Close all open SMB file handles whose file_number matches the share's
    filesystem path. Returns the count of handles closed."""
    target_file_id = get_file_id_for_path(fs_path)

    all_handles = api("GET", "/v1/smb/files/")
    matching = [
        fh for fh in all_handles["file_handles"]
        if fh["file_number"] == target_file_id
    ]

    if not matching:
        print(f"  No open file handles on {fs_path}")
        return 0

    if dry_run:
        print(f"  [DRY-RUN] Would close {len(matching)} file handles on {fs_path}")
        return len(matching)

    # The close endpoint expects the same objects returned by the list endpoint
    results = api("POST", "/v1/smb/files/close", matching)

    errors = [r for r in results if r.get("error_message")]
    closed = len(results) - len(errors)

    print(f"  Closed {closed}/{len(matching)} file handles on {fs_path}")
    for err in errors:
        print(f"    WARNING: {err['error_message']}")

    return closed


# ── Delete share ─────────────────────────────────────────────────────────────

def delete_share(share_id, share_name, dry_run=False):
    """Delete the SMB share via v3 API. Does NOT touch the filesystem."""
    if dry_run:
        print(f"  [DRY-RUN] Would DELETE share '{share_name}' (id={share_id})")
        return

    try:
        api("DELETE", f"/v3/smb/shares/{share_id}")
        print(f"  Share '{share_name}' (id={share_id}) deleted")
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"  ERROR deleting share: HTTP {e.code}: {body}", file=sys.stderr)
        raise


# ── Restore ──────────────────────────────────────────────────────────────────

def restore_share(backup_file, dry_run=False):
    """Recreate an SMB share from a backup JSON file."""
    with open(backup_file) as f:
        config = json.load(f)

    share_name = config["share_name"]

    # Check it doesn't already exist
    existing = get_share_by_name(share_name)
    if existing:
        print(f"  ERROR: Share '{share_name}' already exists (id={existing['id']})")
        sys.exit(1)

    # Build the create payload from backup — strip server-generated fields
    create_payload = {
        "share_name": config["share_name"],
        "fs_path": config["fs_path"],
        "description": config.get("description", ""),
        "tenant_id": config.get("tenant_id", 1),
        "permissions": config["permissions"],
        "network_permissions": config["network_permissions"],
        "access_based_enumeration_enabled": config.get("access_based_enumeration_enabled", False),
        "default_file_create_mode": config.get("default_file_create_mode", "0644"),
        "default_directory_create_mode": config.get("default_directory_create_mode", "0755"),
        "require_encryption": config.get("require_encryption", False),
    }

    if dry_run:
        print(f"  [DRY-RUN] Would recreate share '{share_name}' from {backup_file}")
        print(f"  Payload: {json.dumps(create_payload, indent=2)}")
        return

    result = api("POST", "/v3/smb/shares/", create_payload)
    print(f"  Share '{share_name}' restored (new id={result['id']})")
    print(f"  Path: {result['fs_path']}")
    return result


# ── Verify ───────────────────────────────────────────────────────────────────

def verify_state(share_name, fs_path):
    """Post-operation verification: share gone, filesystem intact, sessions checked."""
    print("\n── Verification ──")

    # Share should be gone
    existing = get_share_by_name(share_name)
    if existing:
        print(f"  WARNING: Share '{share_name}' still exists (id={existing['id']})")
    else:
        print(f"  Share '{share_name}': deleted (confirmed)")

    # Filesystem should be intact
    try:
        encoded = urllib.parse.quote(fs_path, safe="")
        attrs = api("GET", f"/v1/files/{encoded}/info/attributes")
        print(f"  Filesystem '{fs_path}': intact ({attrs['child_count']} children)")
    except urllib.error.HTTPError:
        print(f"  Filesystem '{fs_path}': NOT FOUND (unexpected)")

    # Show surviving sessions
    sessions = api("GET", "/v1/smb/sessions/")
    if sessions["session_infos"]:
        print(f"  Active SMB sessions: {len(sessions['session_infos'])}")
        for s in sessions["session_infos"]:
            user = s["user"].get("name", s["user"].get("sid", "unknown"))
            print(f"    {user} → shares: {s['share_names']}, opens: {s['num_opens']}")
    else:
        print("  Active SMB sessions: none")

    # Show remaining file handles
    handles = api("GET", "/v1/smb/files/")
    print(f"  Open file handles: {len(handles['file_handles'])}")


# ── Orchestration ────────────────────────────────────────────────────────────

def remove_share(share_name, dry_run=False):
    """Full cutover workflow: backup → lockout → close handles → delete."""
    print(f"{'[DRY-RUN] ' if dry_run else ''}Removing share: {share_name}\n")

    # Look up share
    share = get_share_by_name(share_name)
    if not share:
        print(f"ERROR: Share '{share_name}' not found", file=sys.stderr)
        sys.exit(1)

    share_id = share["id"]
    fs_path = share["fs_path"]

    print(f"  Share ID: {share_id}")
    print(f"  Filesystem path: {fs_path}")
    print(f"  Tenant: {share.get('tenant_id', '?')}")
    print()

    # Step 1: Backup
    print("Step 1: Backup share configuration")
    backup_file = backup_share(share, dry_run=dry_run)
    print()

    # Step 2: Network lockout — deny all hosts
    print("Step 2: Apply network lockout (deny all hosts)")
    lockout_share(share_id, dry_run=dry_run)
    if not dry_run:
        # Brief pause to let the deny rule propagate to SMB subsystem
        time.sleep(2)
    print()

    # Step 3: Close file handles on this share
    print("Step 3: Close file handles")
    close_share_handles(fs_path, dry_run=dry_run)
    print()

    # Step 4: Delete the share
    print("Step 4: Delete share")
    delete_share(share_id, share_name, dry_run=dry_run)
    print()

    # Step 5: Verify
    if not dry_run:
        verify_state(share_name, fs_path)
    else:
        print("[DRY-RUN] Skipping verification")

    print(f"\nBackup: {backup_file}")
    print(f"Restore with: python3 {__file__} restore --backup {backup_file}")


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="SMB Share Cutover Tool for Qumulo Clusters",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--host", required=True,
        help="Qumulo cluster hostname or IP",
    )
    parser.add_argument(
        "--creds-file", default=DEFAULT_CREDS,
        help=f"Path to credentials JSON file (default: {DEFAULT_CREDS})",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # list-shares
    sub.add_parser("list-shares", help="List all SMB shares with session counts")

    # list-share
    ls = sub.add_parser("list-share", help="Show sessions for a specific share")
    ls.add_argument("--id", required=True, help="Share ID number")

    # disable
    ds = sub.add_parser("disable", help="Disable a share (lockout + close handles)")
    ds.add_argument("--id", required=True, help="Share ID number to disable")
    ds.add_argument("--dry-run", action="store_true", help="Show what would happen")

    # remove
    rm = sub.add_parser("remove", help="Remove an SMB share (with backup)")
    rm.add_argument("--share", required=True, help="Share name to remove")
    rm.add_argument("--dry-run", action="store_true", help="Show what would happen")

    # restore
    rs = sub.add_parser("restore", help="Restore an SMB share from backup")
    rs.add_argument("--backup", required=True, help="Path to backup JSON file")
    rs.add_argument("--dry-run", action="store_true", help="Show what would happen")

    args = parser.parse_args()

    init_connection(args.host, args.creds_file)

    if args.command == "list-shares":
        list_all_shares()
    elif args.command == "list-share":
        list_share(args.id)
    elif args.command == "disable":
        disable_share(args.id, dry_run=args.dry_run)
    elif args.command == "remove":
        remove_share(args.share, dry_run=args.dry_run)
    elif args.command == "restore":
        restore_share(args.backup, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
