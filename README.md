<details>
<summary><strong>FULL DISCLOSURE</strong> — AI Development & Legal Notice</summary>

---

### AI Development Disclosure

This tool is part of the **pr0t31n toolkit**, a collection of security testing and penetration testing automation tools. The toolkit was created through AI-assisted development, guided by the professional experience and domain expertise of a cybersecurity consultant and penetration tester. Ya, I named it after myself - but to be fair, AI is horrible at naming things.

**The pr0t31n toolkit exists to serve two purposes:**

1. **Automate repetitive penetration testing workflow steps.** Security assessments involve significant amounts of repetitive, procedural work — running sequential tool chains, parsing outputs, correlating findings across tools, and managing engagement data. Automating these steps frees testers to focus on the work that requires human judgment: manual testing, creative attack paths, analysis, and reporting.

2. **Demonstrate the benefits and failures of AI-assisted development.** This toolkit is a real-world case study in building production security tooling with AI assistance. It demonstrates both what AI-assisted development can accomplish and where it falls short. The quality of AI-generated code varies significantly — between context refreshes, the output can range from senior/principal-level software engineering to the work of a still-in-school intern. This inconsistency is itself part of the demonstration.

In the interest of transparency, every tool in the pr0t31n toolkit carries this disclosure. The creator believes that AI-assisted development should be acknowledged openly, not concealed. Users, reviewers, and anyone examining this code should know how it was built so they can evaluate it accordingly.

---

### Legal & Authorization Notice

> **⚠ WARNING: AUTHORIZED USE ONLY**

This tool is designed and intended **exclusively** for use in **authorized security testing engagements**. "Authorized" means **all** of the following conditions are met:

- **Explicit Written Permission.** You possess explicit, documented, written authorization from the owner or authorized representative of the target system(s), network(s), or application(s) to conduct security testing. Verbal agreements are not sufficient.
- **Defined Scope.** The authorization clearly defines the scope of testing, including which systems, networks, IP ranges, applications, and/or endpoints are included. You must not exceed the boundaries of this defined scope under any circumstances.
- **Defined Timeframe.** The authorization specifies the dates and times during which testing is permitted. Testing outside the authorized window is unauthorized testing.
- **Rules of Engagement.** You are operating under a set of rules of engagement (RoE) or equivalent governing document that establishes acceptable testing methods, escalation procedures, emergency contacts, and any restrictions or exclusions.
- **Legal Compliance.** Your testing complies with all applicable local, state, national, and international laws and regulations, including but not limited to the Computer Fraud and Abuse Act (CFAA), the General Data Protection Regulation (GDPR), and equivalent legislation in your jurisdiction.

**Prohibited uses** include but are not limited to: unauthorized access to or testing of any system; testing against systems without explicit written authorization; any activity that violates applicable laws; use for malicious purposes including data theft, extortion, sabotage, or disruption of services; distribution intended to facilitate unauthorized access; and use without a clear legal basis.

**THIS TOOL IS PROVIDED "AS IS," WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT.**

The creator(s) and contributor(s) accept no responsibility or liability for any damage, loss, legal consequence, or other harm resulting from the use or misuse of this tool — including damage to systems or data, legal penalties or prosecution, loss of data or revenue, and any direct, indirect, incidental, special, consequential, or punitive damages.

**By using this tool, you acknowledge that you are solely responsible for ensuring that your use is authorized, lawful, and within the defined scope of your engagement. You assume all risk associated with the use of this tool.**

Security testing is a professional discipline with significant ethical and legal obligations. Users operating in a professional capacity are expected to adhere to the standards and codes of conduct established by recognized industry bodies, including PTES, OWASP, NIST, and any certifying body under which they hold credentials.

---

</details>

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
