# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.1] - 2026-03-03

### Fixed

- Share names containing `$` no longer produce problematic backup filenames (`$` is replaced with `_`)
- Printed shell commands (restore/re-enable hints) are now single-quoted so `$` in paths is not shell-expanded when copy-pasted

## [1.2.0] - 2026-03-03

### Added

- `enable` command: re-enable a previously disabled share by restoring its original network permissions from a backup file
- `restore` now shows a helpful error when the share already exists and is disabled, suggesting `enable` instead
- `disable` now prints an `enable` hint (instead of `restore`) in its post-operation output

## [1.1.0] - 2026-02-13

### Added

- Windows compatibility: ASCII table fallback for legacy consoles, UTF-8 stdout setup
- Restore hint now includes `--host` flag so the command can be copied and run directly
- API error responses now include the server's error body for easier troubleshooting

### Fixed

- v3 SMB shares API used for all write operations (v2 is blocked on multi-tenant clusters)
- Graceful handling of shares whose filesystem path no longer exists (lockout and handle-close steps are skipped with a warning instead of crashing)
- Removed noisy stderr output when API errors are handled internally

### Removed

- Unused `import os` and `import io`

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
