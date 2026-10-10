"""WAForensic command-line interface.

Authorized use only: examine devices and data you own, or that you have
explicit consent / legal authority to examine.
"""
import argparse
import json
import os
import sys

from . import __version__

APP_IDS = {
    "whatsapp": "com.whatsapp",
    "business": "com.whatsapp.w4b",
}

# WhatsApp moved its on-device folder with scoped storage (Android 11+).
# Probe every known location and pull whichever exists.
CANDIDATE_PATHS = {
    "whatsapp": ["/sdcard/Android/media/com.whatsapp/WhatsApp",
                 "/sdcard/WhatsApp"],
    "business": ["/sdcard/Android/media/com.whatsapp.w4b/WhatsApp Business",
                 "/sdcard/WhatsApp Business"],
}


def _app_id(name):
    return APP_IDS.get(name, name)


def _remote_exists(path):
    import subprocess
    r = subprocess.run(["adb", "shell", "ls", path],
                       capture_output=True, text=True)
    return r.returncode == 0


def cmd_carve(a):
    from .disk import SectorReader
    from .carver import carve_image
    with SectorReader(a.image, sector_size=a.sector_size) as r:
        print("[*] Image: %s (%.1f MB, %d sectors)" %
              (a.image, r.size / 1e6, r.sector_count))
        manifest = carve_image(r, a.out,
                               progress=lambda n: print("\r[*] carved %d" % n, end=""))
    print("\n[+] %d files carved -> %s" % (len(manifest), a.out))
    with open(os.path.join(a.out, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)


def cmd_decrypt(a):
    from .crypt import decrypt_file
    out = decrypt_file(a.backup, a.key, a.out)
    print("[+] Decrypted -> %s" % out)
    print("[*] Verify: sqlite3 %s \"SELECT count(*) FROM sqlite_master;\"" % out)


def cmd_db(a):
    from .db import connect_ro, get_chats, get_messages, recover_deleted_fragments
    conn = connect_ro(a.db)
    chats = get_chats(conn)
    msgs = get_messages(conn, limit=a.limit)
    print("[*] %d chats, showing %d newest messages" % (len(chats), len(msgs)))
    out = {"chats": chats, "messages": msgs}
    if a.recover_deleted:
        frags = recover_deleted_fragments(a.db)
        print("[*] %d possible deleted fragments (heuristic — review each)" % len(frags))
        out["deleted_fragments"] = frags
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, default=str)
    print("[+] Wrote %s" % a.out)


def cmd_exif(a):
    from .exif import summarize
    for p in a.photos:
        print("== %s" % p)
        for k, v in summarize(p).items():
            print("   %-16s %s" % (k, v))


def cmd_acquire(a):
    """Pull WhatsApp data over USB via adb (no root needed for /sdcard).

    Deep block-level acquisition (dd of /dev/block/...) additionally needs a
    rooted device with USB debugging enabled and the screen unlocked.
    """
    import shutil
    import subprocess
    if not shutil.which("adb"):
        sys.exit("adb not found on PATH — install Android platform-tools first")
    app = _app_id(a.app)
    dest = a.out
    os.makedirs(dest, exist_ok=True)
    src = None
    for cand in CANDIDATE_PATHS.get(a.app, []):
        if _remote_exists(cand):
            src = cand
            break
    if not src:
        sys.exit("[-] No WhatsApp data folder found on the device. Tried: %s\n"
                 "    Is WhatsApp installed with local backups enabled?"
                 % ", ".join(CANDIDATE_PATHS.get(a.app, [])))
    print("[*] Pulling %s ..." % src)
    r = subprocess.run(["adb", "pull", src, dest], capture_output=True, text=True)
    print(r.stdout[-500:] if r.returncode == 0 else r.stderr[-500:])
    if a.deep:
        print("[*] Attempting block-level dump (needs root)...")
        r = subprocess.run(
            ["adb", "shell", "su -c 'dd if=/dev/block/mmcblk0 bs=4M'"],
            capture_output=True)
        if r.returncode == 0 and r.stdout:
            with open(os.path.join(dest, "mmcblk0.img"), "wb") as f:
                f.write(r.stdout)
            print("[+] Block image saved")
        else:
            print("[-] Block dump failed — device not rooted or su denied. "
                  "File-level pull above is still usable.")


def cmd_report(a):
    from .report import build_report
    findings = {"carved": [], "messages": [], "deleted_fragments": [],
                "notes": []}
    if a.manifest and os.path.isfile(a.manifest):
        findings["carved"] = json.load(open(a.manifest))
    if a.db_json and os.path.isfile(a.db_json):
        d = json.load(open(a.db_json))
        findings["messages"] = d.get("messages", [])
        findings["deleted_fragments"] = d.get("deleted_fragments", [])
    p = build_report(findings, a.out, case_name=a.case)
    print("[+] Report -> %s" % p)


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="waforensic",
        description="Android & WhatsApp forensic recovery toolkit (v%s). "
                    "For authorized examination of your own devices/data only." % __version__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("carve", help="Carve deleted files from a raw disk image")
    c.add_argument("image", help="Path to dd image (or block device)")
    c.add_argument("-o", "--out", default="carved", help="Output directory")
    c.add_argument("--sector-size", type=int, default=512)
    c.set_defaults(f=cmd_carve)

    d = sub.add_parser("decrypt", help="Decrypt msgstore.db.crypt12/14/15")
    d.add_argument("backup", help="Encrypted backup file")
    d.add_argument("key", help="158-byte key file, 32-byte raw key, or 64-char hex")
    d.add_argument("-o", "--out", default="msgstore.db")
    d.set_defaults(f=cmd_decrypt)

    b = sub.add_parser("db", help="Parse msgstore.db: chats, messages, deleted fragments")
    b.add_argument("db", help="Decrypted SQLite database")
    b.add_argument("--limit", type=int, default=1000)
    b.add_argument("--recover-deleted", action="store_true")
    b.add_argument("-o", "--out", default="messages.json")
    b.set_defaults(f=cmd_db)

    e = sub.add_parser("exif", help="Extract EXIF/GPS metadata from photos")
    e.add_argument("photos", nargs="+")
    e.set_defaults(f=cmd_exif)

    q = sub.add_parser("acquire", help="Pull WhatsApp data from a USB-connected phone via adb")
    q.add_argument("--app", default="whatsapp", choices=["whatsapp", "business"])
    q.add_argument("--deep", action="store_true", help="Also try block-level dd (needs root)")
    q.add_argument("-o", "--out", default="acquired")
    q.set_defaults(f=cmd_acquire)

    r = sub.add_parser("report", help="Build the interactive HTML analysis report")
    r.add_argument("--manifest", help="carve manifest.json")
    r.add_argument("--db-json", help="db command output JSON")
    r.add_argument("--case", default="WAForensic case")
    r.add_argument("-o", "--out", default="report.html")
    r.set_defaults(f=cmd_report)

    a = ap.parse_args(argv)
    a.f(a)


if __name__ == "__main__":
    main()
