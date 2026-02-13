# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-02-13

### Added

- `list-shares` command: show all SMB shares with session counts and disabled status
- `list-share` command: show detailed session table for a specific share
- `disable` command: lock out a share via DENY 0.0.0.0/0 network rule and close file handles
- `remove` command: back up, lock out, close handles, and delete a share
- `restore` command: recreate a share from a backup JSON file
- Automatic backup of share configuration before any destructive operation
- `hide_shares_from_unauthorized_hosts` is enabled automatically when applying a network lockout
- Disabled share detection in `list-shares` output
- `--dry-run` support for `disable`, `remove`, and `restore` commands
- `--host` (required) and `--creds-file` global options
- `--version` flag
- Post-operation verification for `remove` (confirms share deleted, filesystem intact, other sessions alive)
