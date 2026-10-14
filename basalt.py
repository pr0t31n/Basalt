#!/usr/bin/env python3
"""Basalt — Encrypted File-Level Backup & Restore Tool."""
import argparse
import getpass
import hashlib
import hmac as _hmac
import json
import os
import platform
import shutil
import struct
import sys
import tarfile
import tempfile
import time
import uuid
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path

if getattr(sys, "frozen", False):
    _BASE = Path(sys._MEIPASS)
else:
    _BASE = Path(__file__).resolve().parent
VERSION = _BASE.joinpath("VERSION").read_text().strip()

MAGIC = b"BSLT"
FMT_VER = 1
PBKDF2_ITER = 600_000
SALT_LEN = 32
IV_LEN = 16
HMAC_LEN = 32
CHUNK = 64 * 1024

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False


def _require_crypto():
    if not _HAS_CRYPTO:
        print("ERROR: 'cryptography' package required.\n"
              "  Install: pip install cryptography", file=sys.stderr)
        sys.exit(1)


def _derive_keys(passphrase, salt, iterations=PBKDF2_ITER):
    dk = hashlib.pbkdf2_hmac(
        "sha256", passphrase.encode("utf-8"), salt, iterations, dklen=64)
    return dk[:32], dk[32:]


def _hash_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def _human(n):
    for u in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} PB"


def _get_passphrase(confirm=False, passphrase_file=None):
    if passphrase_file:
        p = Path(passphrase_file).read_text(encoding="utf-8").splitlines()[0]
    else:
        p = getpass.getpass("Encryption passphrase: ")
        if confirm:
            if getpass.getpass("Confirm passphrase: ") != p:
                print("ERROR: Passphrases do not match", file=sys.stderr)
                sys.exit(1)
    if not p:
        print("ERROR: Passphrase cannot be empty", file=sys.stderr)
        sys.exit(1)
    return p


def _build_manifest(sources):
    entries = []
    for idx, src in enumerate(sources):
        sp = Path(src).resolve()
        if not sp.exists():
            print(f"ERROR: Source does not exist: {sp}", file=sys.stderr)
            sys.exit(1)
        if sp.is_file():
            st = sp.stat()
            entries.append({
                "source_index": idx,
                "relative_path": sp.name,
                "size": st.st_size,
                "mtime": st.st_mtime,
                "sha256": _hash_file(sp),
            })
            continue
        count = 0
        for root, _dirs, files in os.walk(sp):
            for fn in sorted(files):
                fp = Path(root) / fn
                if not fp.is_file():
                    continue
                try:
                    st = fp.stat()
                    entries.append({
                        "source_index": idx,
                        "relative_path": str(fp.relative_to(sp)),
                        "size": st.st_size,
                        "mtime": st.st_mtime,
                        "sha256": _hash_file(fp),
                    })
                    count += 1
                    if count % 500 == 0:
                        print(f"    scanned {count} files...", end="\r")
                except (PermissionError, OSError) as e:
                    print(f"  WARN: skip {fp}: {e}", file=sys.stderr)
        if count >= 500:
            print()
    return entries


# ── Archive I/O ──────────────────────────────────────────────────

def _write_basalt(tar_path, dest_path, header_dict, aes_key, hmac_key, iv):
    header = json.dumps(header_dict).encode("utf-8")
    hmac_obj = _hmac.new(hmac_key, digestmod="sha256")
    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(iv))
    enc = cipher.encryptor()
    with open(dest_path, "wb") as out:
        preamble = MAGIC + struct.pack("<HI", FMT_VER, len(header)) + header
        out.write(preamble)
        hmac_obj.update(preamble)
        with open(tar_path, "rb") as inp:
            for chunk in iter(lambda: inp.read(CHUNK), b""):
                ct = enc.update(chunk)
                out.write(ct)
                hmac_obj.update(ct)
        ct_final = enc.finalize()
        if ct_final:
            out.write(ct_final)
            hmac_obj.update(ct_final)
        out.write(hmac_obj.digest())


def _read_basalt_header(path):
    with open(path, "rb") as f:
        magic = f.read(4)
        if magic != MAGIC:
            print(f"ERROR: Not a Basalt archive: {path}", file=sys.stderr)
            sys.exit(1)
        ver, hlen = struct.unpack("<HI", f.read(6))
        header = json.loads(f.read(hlen).decode("utf-8"))
    return header, 10 + hlen


def _verify_hmac(path, hmac_key, preamble_end):
    fsize = os.path.getsize(path)
    if fsize < preamble_end + HMAC_LEN:
        return False
    hmac_obj = _hmac.new(hmac_key, digestmod="sha256")
    data_end = fsize - HMAC_LEN
    with open(path, "rb") as f:
        remaining = data_end
        while remaining > 0:
            chunk = f.read(min(CHUNK, remaining))
            if not chunk:
                break
            hmac_obj.update(chunk)
            remaining -= len(chunk)
        stored_tag = f.read(HMAC_LEN)
    return _hmac.compare_digest(hmac_obj.digest(), stored_tag)


def _decrypt_to_file(basalt_path, out_path, aes_key, preamble_end):
    fsize = os.path.getsize(basalt_path)
    payload_end = fsize - HMAC_LEN
    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(
        bytes.fromhex(_read_basalt_header(basalt_path)[0]["iv"])))
    dec = cipher.decryptor()
    with open(basalt_path, "rb") as inp, open(out_path, "wb") as out:
        inp.seek(preamble_end)
        remaining = payload_end - preamble_end
        while remaining > 0:
            chunk = inp.read(min(CHUNK, remaining))
            if not chunk:
                break
            out.write(dec.update(chunk))
            remaining -= len(chunk)
        final = dec.finalize()
        if final:
            out.write(final)


def _extract_manifest(tar_path):
    with tarfile.open(tar_path, "r:gz") as tar:
        try:
            mf = tar.extractfile("_basalt_manifest.json")
            if mf:
                return json.loads(mf.read().decode("utf-8"))
        except KeyError:
            pass
    return None


# ── Commands ─────────────────────────────────────────────────────

def cmd_backup(args):
    _require_crypto()
    sources = [Path(s).resolve() for s in args.source]
    dest = Path(args.dest).resolve()
    dest.mkdir(parents=True, exist_ok=True)

    passphrase = _get_passphrase(confirm=True, passphrase_file=args.passphrase_file)
    backup_id = str(uuid.uuid4())
    ts = datetime.now(timezone.utc)

    print(f"\nBasalt v{VERSION} — Backup")
    print(f"  Backup ID : {backup_id}")
    print(f"  Timestamp : {ts.isoformat()}")
    for i, s in enumerate(sources):
        print(f"  Source [{i}] : {s}")
    print(f"  Dest      : {dest}\n")

    # Phase 1: scan + hash
    print("Phase 1/4: Scanning and hashing source files...")
    t0 = time.time()
    manifest_entries = _build_manifest([str(s) for s in sources])
    total_files = len(manifest_entries)
    total_bytes = sum(e["size"] for e in manifest_entries)
    print(f"  {total_files} files, {_human(total_bytes)} "
          f"({time.time() - t0:.1f}s)\n")

    if total_files == 0:
        print("Nothing to back up — source directories are empty.")
        return

    # Phase 2: tar + compress (driven by manifest — only adds files Phase 1 scanned)
    print("Phase 2/4: Creating compressed archive...")
    t1 = time.time()
    skip_count = 0
    tmp_tar = tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False)
    try:
        with tarfile.open(tmp_tar.name, "w:gz", compresslevel=6) as tar:
            for entry in manifest_entries:
                si = entry["source_index"]
                s = sources[si]
                if s.is_file():
                    fp = s
                    arcname = f"{si}/{s.name}"
                else:
                    fp = s / entry["relative_path"]
                    arcname = f"{si}/{entry['relative_path']}"
                try:
                    tar.add(str(fp), arcname=arcname, recursive=False)
                except (PermissionError, OSError) as e:
                    print(f"  WARN: tar skip {fp}: {e}", file=sys.stderr)
                    skip_count += 1
            if skip_count:
                print(f"  {skip_count} files skipped (permission denied)")
            mbytes = json.dumps({
                "backup_id": backup_id,
                "basalt_version": VERSION,
                "timestamp": ts.isoformat(),
                "hostname": platform.node(),
                "os": f"{platform.system()} {platform.release()}",
                "sources": [
                    {"index": i, "path": str(s), "is_file": s.is_file()}
                    for i, s in enumerate(sources)
                ],
                "files": manifest_entries,
                "total_files": total_files,
                "total_bytes": total_bytes,
            }, indent=2).encode("utf-8")
            mi = tarfile.TarInfo(name="_basalt_manifest.json")
            mi.size = len(mbytes)
            mi.mtime = time.time()
            tar.addfile(mi, BytesIO(mbytes))

        tar_size = Path(tmp_tar.name).stat().st_size
        ratio = (1 - tar_size / max(total_bytes, 1)) * 100
        print(f"  {_human(tar_size)} compressed ({ratio:.0f}% reduction, "
              f"{time.time() - t1:.1f}s)\n")

        # Phase 3: encrypt
        print("Phase 3/4: Encrypting with AES-256-CTR + HMAC-SHA256...")
        t2 = time.time()
        salt = os.urandom(SALT_LEN)
        iv = os.urandom(IV_LEN)
        aes_key, hmac_key = _derive_keys(passphrase, salt)

        basalt_name = f"{backup_id}.basalt"
        basalt_path = dest / basalt_name

        header_dict = {
            "backup_id": backup_id,
            "format_version": FMT_VER,
            "tool_version": VERSION,
            "timestamp": ts.isoformat(),
            "salt": salt.hex(),
            "iv": iv.hex(),
            "pbkdf2_iterations": PBKDF2_ITER,
            "compression": "gzip",
            "encryption": "AES-256-CTR",
            "authentication": "HMAC-SHA256",
            "key_derivation": "PBKDF2-HMAC-SHA256",
        }
        _write_basalt(tmp_tar.name, str(basalt_path),
                       header_dict, aes_key, hmac_key, iv)
        archive_size = basalt_path.stat().st_size
        print(f"  {_human(archive_size)} encrypted ({time.time() - t2:.1f}s)\n")

        # Phase 4: sidecar JSON
        print("Phase 4/4: Writing backup manifest...")
        sidecar = {
            "backup_id": backup_id,
            "tool": "basalt",
            "version": VERSION,
            "timestamp": ts.isoformat(),
            "hostname": platform.node(),
            "os": f"{platform.system()} {platform.release()}",
            "source_directories": [
                {
                    "index": i,
                    "path": str(s),
                    "is_file": s.is_file(),
                    "file_count": sum(
                        1 for e in manifest_entries if e["source_index"] == i),
                    "total_bytes": sum(
                        e["size"] for e in manifest_entries
                        if e["source_index"] == i),
                } for i, s in enumerate(sources)
            ],
            "total_files": total_files,
            "total_bytes": total_bytes,
            "archive_file": basalt_name,
            "archive_bytes": archive_size,
            "compression": "gzip",
            "encryption": "AES-256-CTR",
            "authentication": "HMAC-SHA256",
            "key_derivation": "PBKDF2-HMAC-SHA256",
            "pbkdf2_iterations": PBKDF2_ITER,
        }
        sidecar_path = dest / f"{backup_id}.basalt.json"
        sidecar_path.write_text(
            json.dumps(sidecar, indent=2), encoding="utf-8")

        try:
            import sys as _sys
            if "/opt/pr0t31n/shared" not in _sys.path:
                _sys.path.insert(0, "/opt/pr0t31n/shared")
            import pr0t31n_dep_snapshot as _ds
            _ds.write_snapshot(
                dest, "Basalt", VERSION,
                binaries=[],
                pip_packages=["cryptography"],
            )
        except Exception:
            pass

        if args.retain:
            pruned = _do_prune(dest, args.retain)
            if pruned:
                print(f"  Pruned {pruned} old backup(s)\n")

        elapsed = time.time() - t0
        print(f"Backup complete ({elapsed:.1f}s)")
        print(f"  Files   : {total_files}")
        print(f"  Size    : {_human(total_bytes)}")
        print(f"  Archive : {basalt_path}")
        print(f"  Manifest: {sidecar_path}")

    finally:
        try:
            os.unlink(tmp_tar.name)
        except OSError:
            pass


def cmd_restore(args):
    _require_crypto()
    basalt_path = Path(args.archive).resolve()
    if not basalt_path.exists():
        print(f"ERROR: Archive not found: {basalt_path}", file=sys.stderr)
        sys.exit(1)

    sidecar_path = basalt_path.with_suffix(basalt_path.suffix + ".json")
    if not sidecar_path.exists():
        print(f"ERROR: Sidecar manifest not found: {sidecar_path}",
              file=sys.stderr)
        sys.exit(1)

    sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
    passphrase = _get_passphrase(passphrase_file=args.passphrase_file)

    print(f"\nBasalt v{VERSION} — Restore")
    print(f"  Backup ID : {sidecar['backup_id']}")
    print(f"  Created   : {sidecar['timestamp']}")
    print(f"  From host : {sidecar.get('hostname', '?')}")
    print(f"  Files     : {sidecar['total_files']}")
    print(f"  Size      : {_human(sidecar['total_bytes'])}")
    print(f"  Targets:")
    for sd in sidecar["source_directories"]:
        path = args.target or sd["path"]
        print(f"    [{sd['index']}] {path} "
              f"({sd['file_count']} files, {_human(sd['total_bytes'])})")
    print()

    # Phase 1: verify HMAC
    print("Phase 1/6: Verifying archive integrity...")
    header, preamble_end = _read_basalt_header(str(basalt_path))
    salt = bytes.fromhex(header["salt"])
    iters = header.get("pbkdf2_iterations", PBKDF2_ITER)
    aes_key, hmac_key = _derive_keys(passphrase, salt, iters)

    if not _verify_hmac(str(basalt_path), hmac_key, preamble_end):
        print("  FAILED: HMAC verification failed.\n"
              "  The passphrase is wrong or the archive has been "
              "tampered with / corrupted.", file=sys.stderr)
        sys.exit(1)
    print("  HMAC verified — archive is authentic and intact.\n")

    # Phase 2: decrypt
    print("Phase 2/6: Decrypting archive...")
    t0 = time.time()
    tmp_tar = tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False)
    try:
        _decrypt_to_file(str(basalt_path), tmp_tar.name,
                         aes_key, preamble_end)
        print(f"  Decrypted ({time.time() - t0:.1f}s)\n")

        # Phase 3: extract internal manifest
        print("Phase 3/6: Reading internal manifest...")
        manifest = _extract_manifest(tmp_tar.name)
        if not manifest:
            print("ERROR: Internal manifest not found in archive",
                  file=sys.stderr)
            sys.exit(1)
        source_map = {
            s["index"]: s["path"] for s in manifest["sources"]}
        print(f"  {manifest['total_files']} files in manifest\n")

        # Phase 4: create rollback copies
        print("Phase 4/6: Creating pre-restore safety copies...")
        rollback_ts = datetime.now().strftime("%Y%m%dT%H%M%S")
        rollback_dirs = {}
        for sd in sidecar["source_directories"]:
            target = Path(args.target) if args.target else Path(sd["path"])
            if not target.exists():
                print(f"  [{sd['index']}] {target} — does not exist, "
                      "no rollback needed")
                continue
            rb_parent = target.parent / f"_basalt_pre_restore_{rollback_ts}"
            rb_parent.mkdir(parents=True, exist_ok=True)
            rb_dest = rb_parent / target.name
            print(f"  [{sd['index']}] Moving {target} → {rb_dest}")
            shutil.move(str(target), str(rb_dest))
            rollback_dirs[sd["index"]] = {
                "original": str(target),
                "rollback": str(rb_dest),
                "rollback_parent": str(rb_parent),
            }
        print()

        # Phase 5: extract files to original locations
        print("Phase 5/6: Restoring files to original locations...")
        t1 = time.time()
        restored = 0
        with tarfile.open(tmp_tar.name, "r:gz") as tar:
            for member in tar.getmembers():
                if member.name == "_basalt_manifest.json":
                    continue
                parts = member.name.split("/", 1)
                if len(parts) < 2:
                    if member.isdir():
                        idx_str = parts[0]
                        try:
                            idx = int(idx_str)
                        except ValueError:
                            continue
                        target = (Path(args.target) if args.target
                                  else Path(source_map[idx]))
                        target.mkdir(parents=True, exist_ok=True)
                    continue
                idx_str, rel = parts
                try:
                    idx = int(idx_str)
                except ValueError:
                    continue
                target_root = (Path(args.target) if args.target
                               else Path(source_map[idx]))
                target_path = target_root / rel
                if member.isdir():
                    target_path.mkdir(parents=True, exist_ok=True)
                elif member.isfile():
                    target_path.parent.mkdir(parents=True, exist_ok=True)
                    src_f = tar.extractfile(member)
                    if src_f:
                        with open(target_path, "wb") as dst_f:
                            shutil.copyfileobj(src_f, dst_f)
                        try:
                            os.utime(target_path, (member.mtime, member.mtime))
                        except OSError:
                            pass
                        restored += 1
                        if restored % 200 == 0:
                            print(f"    restored {restored} files...",
                                  end="\r")
        if restored >= 200:
            print()
        print(f"  {restored} files restored ({time.time() - t1:.1f}s)\n")

        # Phase 6: verify restored files
        print("Phase 6/6: Verifying restored files against manifest...")
        t2 = time.time()
        ok_count = 0
        fail_count = 0
        failures = []
        for entry in manifest["files"]:
            idx = entry["source_index"]
            target_root = (Path(args.target) if args.target
                           else Path(source_map[idx]))
            fp = target_root / entry["relative_path"]
            if not fp.exists():
                failures.append(f"  MISSING: {fp}")
                fail_count += 1
                continue
            actual_hash = _hash_file(fp)
            if actual_hash != entry["sha256"]:
                failures.append(
                    f"  HASH MISMATCH: {fp}\n"
                    f"    expected: {entry['sha256']}\n"
                    f"    actual  : {actual_hash}")
                fail_count += 1
            else:
                ok_count += 1

        elapsed = time.time() - t2
        print(f"  Verified: {ok_count} OK, {fail_count} failed "
              f"({elapsed:.1f}s)\n")

        if fail_count > 0:
            print("RESTORE VERIFICATION FAILED:")
            for f in failures[:20]:
                print(f)
            if len(failures) > 20:
                print(f"  ... and {len(failures) - 20} more")
            print("\nRolling back to pre-restore state...")
            _do_rollback(rollback_dirs)
            print("Rollback complete. Original data has been restored.")
            sys.exit(1)

        print(f"RESTORE VERIFIED: all {ok_count} files match "
              f"original checksums.\n")

        if not args.auto_confirm:
            confirm = input(
                "Delete pre-restore safety copies? [y/N]: ").strip().lower()
        else:
            confirm = "y"

        if confirm == "y":
            for info in rollback_dirs.values():
                rb_parent = Path(info["rollback_parent"])
                if rb_parent.exists():
                    shutil.rmtree(str(rb_parent))
                    print(f"  Deleted: {rb_parent}")
            print("\nRestore complete — safety copies removed.")
        else:
            print("\nRestore complete — safety copies retained at:")
            for info in rollback_dirs.values():
                print(f"  {info['rollback']}")
            print("Delete them manually when you've confirmed the "
                  "restore is correct.")

    except Exception:
        print("\nERROR: Restore failed unexpectedly. Rolling back...",
              file=sys.stderr)
        import traceback
        traceback.print_exc()
        _do_rollback(rollback_dirs)
        print("Rollback complete. Original data has been restored.")
        sys.exit(1)
    finally:
        try:
            os.unlink(tmp_tar.name)
        except OSError:
            pass


def _do_rollback(rollback_dirs):
    for info in rollback_dirs.values():
        orig = Path(info["original"])
        rb = Path(info["rollback"])
        if not rb.exists():
            continue
        if orig.exists():
            shutil.rmtree(str(orig))
        shutil.move(str(rb), str(orig))
        rb_parent = Path(info["rollback_parent"])
        if rb_parent.exists() and not any(rb_parent.iterdir()):
            rb_parent.rmdir()
    return True


def cmd_verify(args):
    _require_crypto()
    basalt_path = Path(args.archive).resolve()
    if not basalt_path.exists():
        print(f"ERROR: Archive not found: {basalt_path}", file=sys.stderr)
        sys.exit(1)

    passphrase = _get_passphrase(passphrase_file=args.passphrase_file)

    print(f"\nBasalt v{VERSION} — Verify")
    print(f"  Archive: {basalt_path}\n")

    header, preamble_end = _read_basalt_header(str(basalt_path))
    print(f"  Backup ID  : {header['backup_id']}")
    print(f"  Created    : {header['timestamp']}")
    print(f"  Encryption : {header['encryption']}")
    print(f"  Auth       : {header['authentication']}\n")

    salt = bytes.fromhex(header["salt"])
    iters = header.get("pbkdf2_iterations", PBKDF2_ITER)
    aes_key, hmac_key = _derive_keys(passphrase, salt, iters)

    print("Verifying HMAC...")
    if not _verify_hmac(str(basalt_path), hmac_key, preamble_end):
        print("  FAILED: HMAC mismatch — wrong passphrase, "
              "corrupted, or tampered.", file=sys.stderr)
        sys.exit(1)
    print("  HMAC verified — archive is authentic and intact.\n")

    if args.deep:
        print("Deep verify: decrypting and reading manifest...")
        tmp = tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False)
        try:
            _decrypt_to_file(str(basalt_path), tmp.name,
                             aes_key, preamble_end)
            manifest = _extract_manifest(tmp.name)
            if not manifest:
                print("  ERROR: No manifest in archive", file=sys.stderr)
                sys.exit(1)
            print(f"  Files in manifest: {manifest['total_files']}")
            print(f"  Original size    : {_human(manifest['total_bytes'])}")
            source_map = {
                s["index"]: s["path"] for s in manifest["sources"]}
            print(f"  Source dirs      : {len(source_map)}")
            for idx, path in sorted(source_map.items()):
                print(f"    [{idx}] {path}")

            if args.check_current:
                print("\nComparing manifest against current files on disk...")
                ok = 0
                changed = 0
                missing = 0
                for entry in manifest["files"]:
                    fp = Path(source_map[entry["source_index"]]) / entry["relative_path"]
                    if not fp.exists():
                        missing += 1
                        continue
                    if _hash_file(fp) == entry["sha256"]:
                        ok += 1
                    else:
                        changed += 1
                print(f"  Unchanged : {ok}")
                print(f"  Changed   : {changed}")
                print(f"  Missing   : {missing}")
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass

    print("\nVerification passed.")


def cmd_list(args):
    dest = Path(args.dest).resolve()
    if not dest.exists():
        print(f"No backups found in {dest}")
        return

    sidecars = sorted(dest.glob("*.basalt.json"),
                      key=lambda p: p.stat().st_mtime, reverse=True)
    if not sidecars:
        print(f"No Basalt backups found in {dest}")
        return

    print(f"\nBasalt backups in {dest}:\n")
    print(f"{'#':>3}  {'Timestamp':<25} {'Files':>7} {'Size':>10} "
          f"{'Archive':>10}  {'Host':<15} ID")
    print("─" * 100)

    for i, sp in enumerate(sidecars, 1):
        try:
            s = json.loads(sp.read_text(encoding="utf-8"))
            archive = dest / s.get("archive_file", "?")
            arch_size = (_human(archive.stat().st_size)
                         if archive.exists() else "MISSING")
            print(f"{i:>3}  {s.get('timestamp', '?'):<25} "
                  f"{s.get('total_files', 0):>7} "
                  f"{_human(s.get('total_bytes', 0)):>10} "
                  f"{arch_size:>10}  "
                  f"{s.get('hostname', '?'):<15} "
                  f"{s.get('backup_id', '?')[:8]}...")
        except (json.JSONDecodeError, OSError):
            print(f"{i:>3}  ERROR reading {sp.name}")

    print(f"\n{len(sidecars)} backup(s) found.")


def cmd_prune(args):
    dest = Path(args.dest).resolve()
    pruned = _do_prune(dest, args.retain)
    if pruned:
        print(f"Pruned {pruned} old backup(s), keeping newest {args.retain}.")
    else:
        print(f"Nothing to prune (have <= {args.retain} backups).")


def _do_prune(dest, retain):
    sidecars = sorted(dest.glob("*.basalt.json"),
                      key=lambda p: p.stat().st_mtime, reverse=True)
    if len(sidecars) <= retain:
        return 0
    pruned = 0
    for sp in sidecars[retain:]:
        try:
            s = json.loads(sp.read_text(encoding="utf-8"))
            archive = dest / s.get("archive_file", "")
            if archive.exists():
                archive.unlink()
            sp.unlink()
            pruned += 1
        except (json.JSONDecodeError, OSError) as e:
            print(f"  WARN: Could not prune {sp.name}: {e}",
                  file=sys.stderr)
    return pruned


# ── CLI ──────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        prog="basalt",
        description=f"Basalt v{VERSION} — Encrypted File-Level "
                    "Backup & Restore")
    p.add_argument("--version", "-V", action="version",
                   version=f"Basalt v{VERSION}")
    sub = p.add_subparsers(dest="command", required=True)

    # backup
    bp = sub.add_parser("backup", help="Create an encrypted backup")
    bp.add_argument("--source", "-s", action="append", required=True,
                    help="Source directory or file (repeatable)")
    bp.add_argument("--dest", "-d", required=True,
                    help="Destination directory (e.g. external drive)")
    bp.add_argument("--retain", "-r", type=int, default=None,
                    help="Keep only the N newest backups in dest")
    bp.add_argument("--passphrase-file", default=None,
                    help="Read passphrase from file (first line)")

    # restore
    rp = sub.add_parser("restore", help="Restore from an encrypted backup")
    rp.add_argument("--archive", "-a", required=True,
                    help="Path to the .basalt archive file")
    rp.add_argument("--target", "-t", default=None,
                    help="Override restore target (default: original paths)")
    rp.add_argument("--passphrase-file", default=None,
                    help="Read passphrase from file (first line)")
    rp.add_argument("--auto-confirm", "-y", action="store_true",
                    help="Skip confirmation prompt after verification")

    # verify
    vp = sub.add_parser("verify", help="Verify archive integrity")
    vp.add_argument("--archive", "-a", required=True,
                    help="Path to the .basalt archive file")
    vp.add_argument("--passphrase-file", default=None,
                    help="Read passphrase from file (first line)")
    vp.add_argument("--deep", action="store_true",
                    help="Decrypt and read internal manifest")
    vp.add_argument("--check-current", action="store_true",
                    help="Compare manifest against current files on disk "
                    "(requires --deep)")

    # list
    lp = sub.add_parser("list", help="List backups in a directory")
    lp.add_argument("--dest", "-d", required=True,
                    help="Backup destination directory to list")

    # prune
    pp = sub.add_parser("prune", help="Delete old backups, keep newest N")
    pp.add_argument("--dest", "-d", required=True,
                    help="Backup destination directory")
    pp.add_argument("--retain", "-r", type=int, required=True,
                    help="Number of newest backups to keep")

    args = p.parse_args()
    cmds = {
        "backup": cmd_backup,
        "restore": cmd_restore,
        "verify": cmd_verify,
        "list": cmd_list,
        "prune": cmd_prune,
    }
    cmds[args.command](args)


if __name__ == "__main__":
    main()
