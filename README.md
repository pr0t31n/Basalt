# Basalt

Encrypted file-level backup and restore tool with cryptographic validation and atomic rollback.

## Features

- **AES-256-CTR encryption** with HMAC-SHA256 authentication (Encrypt-then-MAC)
- **PBKDF2-HMAC-SHA256** key derivation (600,000 iterations, NIST SP 800-132)
- **SHA-256 file tree** manifest for cryptographic restore validation
- **4-phase atomic restore** with automatic rollback on failure
- **Backup rotation** with `--retain N` to keep only the newest backups
- **Cross-platform** — Windows, macOS, Linux
- **Single-file archives** (`.basalt`) with JSON sidecar manifests

## Requirements

- Python 3.10+
- `cryptography` package (`pip install cryptography`)

## Installation

```bash
cd /opt/pr0t31n/Basalt
python3 install.py
```

## Usage

### Backup

Create an encrypted backup of one or more directories to an external drive:

```bash
python3 basalt.py backup \
  --source /path/to/documents \
  --source /path/to/configs \
  --dest /mnt/external/backups
```

With retention (keep only 5 newest backups):

```bash
python3 basalt.py backup \
  -s /data/important \
  -d /mnt/usb/backups \
  --retain 5
```

### Restore

Restore from a backup archive to the original locations:

```bash
python3 basalt.py restore --archive /mnt/external/backups/<uuid>.basalt
```

Restore to a different target directory:

```bash
python3 basalt.py restore \
  -a /mnt/external/backups/<uuid>.basalt \
  --target /tmp/restored
```

The restore process:
1. Verifies archive integrity (HMAC-SHA256)
2. Decrypts the archive
3. Moves existing target directories to safety copies
4. Extracts files to original (or target) locations
5. Verifies every restored file against SHA-256 manifest
6. On success: prompts to delete safety copies
7. On failure: automatically rolls back to pre-restore state

### Verify

Check archive integrity without restoring:

```bash
python3 basalt.py verify -a /mnt/external/backups/<uuid>.basalt
```

Deep verification (decrypt and inspect manifest):

```bash
python3 basalt.py verify -a /mnt/external/backups/<uuid>.basalt --deep
```

Compare backup manifest against current files on disk:

```bash
python3 basalt.py verify -a /mnt/external/backups/<uuid>.basalt --deep --check-current
```

### List

List all backups in a directory:

```bash
python3 basalt.py list -d /mnt/external/backups
```

### Prune

Delete old backups, keeping only the N newest:

```bash
python3 basalt.py prune -d /mnt/external/backups --retain 5
```

## Archive Format

Each backup produces two files:

- `<uuid>.basalt` — Encrypted archive
- `<uuid>.basalt.json` — Plaintext sidecar manifest

### `.basalt` Binary Format

| Offset | Size | Content |
|--------|------|---------|
| 0 | 4 | Magic: `BSLT` |
| 4 | 2 | Format version (uint16 LE) |
| 6 | 4 | Header length (uint32 LE) |
| 10 | N | JSON header (plaintext): backup ID, salt, IV, PBKDF2 params |
| 10+N | M | AES-256-CTR encrypted payload (gzip-compressed tar) |
| 10+N+M | 32 | HMAC-SHA256 authentication tag |

The encrypted payload contains:
- All source files organized by source index (`0/`, `1/`, etc.)
- `_basalt_manifest.json` with per-file SHA-256 hashes

### Sidecar JSON

Contains backup metadata: source paths, timestamps, file counts, sizes, hostname, OS info. Used by the restore command to determine original target paths.

## Security

- **Encryption**: AES-256-CTR (NIST approved)
- **Authentication**: HMAC-SHA256 (Encrypt-then-MAC)
- **Key derivation**: PBKDF2-HMAC-SHA256, 600,000 iterations (NIST SP 800-132)
- **Salt**: 32 bytes, cryptographically random per backup
- **IV**: 16 bytes, cryptographically random per backup
- Passphrases never stored; only PBKDF2-derived keys used
- HMAC verified before any decryption (prevents oracle attacks)

### Compliance Alignment

| Framework | Controls |
|-----------|----------|
| NIST SP 800-171 r3 | 3.13.16 (Data at Rest), 3.8.9 (Media Protection) |
| NIST SP 800-34 | Backup and recovery planning |
| NIST SP 800-132 | Key derivation (PBKDF2 parameters) |
| PCI DSS 4.0 | 3.5.1 (Encryption of stored data) |

## Passphrase Management

- Interactive: prompted via `getpass` (not visible in terminal)
- Non-interactive: `--passphrase-file /path/to/file` (reads first line)
- Passphrases never appear in CLI arguments (not visible in `ps` output)

## Limitations (v1)

- File-level backup only (no disk imaging or bare-metal)
- No scheduling (use cron/Task Scheduler)
- No incremental or differential backups
- No network destinations (local/mounted drives only)
- No GUI
- Windows ACLs not preserved (file content and timestamps are preserved)

## Integration

Basalt is part of the pr0t31n toolkit. It integrates with Arsenal for version management and installation.
