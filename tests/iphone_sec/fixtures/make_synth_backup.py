#!/usr/bin/env python3
"""Build a tiny fake iTunes-style backup folder (no phone involved).

usage: make_synth_backup.py DEST_DIR [--evil] [--encrypted] [--passcode true|false|missing]
  --evil       add a manifest row named evil.db (matches fixtures/synth.stix2)
  --encrypted  make Manifest.db unreadable (not SQLite), like an encrypted backup
  --incomplete do not create any of the stored files the manifest lists
  --partial    create the stored files for every manifest row but one (MVT then reports files missing from the backup)
  --no-db      leave Manifest.db out          --no-plist   leave Manifest.plist out
  --no-encflag Manifest.plist without IsEncrypted
  --bad-plist  Manifest.plist that is not a plist    --list-plist  Manifest.plist that is a list, not a dict
"""
import os, plistlib, sqlite3, sys

dest = sys.argv[1]
evil = "--evil" in sys.argv
encrypted = "--encrypted" in sys.argv
passcode = "true"
if "--passcode" in sys.argv:
    passcode = sys.argv[sys.argv.index("--passcode") + 1]

os.makedirs(dest, exist_ok=True)
info = {
    "Build Version": "24B119", "Device Name": "Test Phone", "Display Name": "Test Phone",
    "GUID": "AAAA", "Product Name": "iPhone 17 Pro", "Product Type": "iPhone18,2",
    "Product Version": "27.2", "Serial Number": "SYNTH0001",
    "Target Identifier": "00008150-0000000000000001", "Target Type": "Device",
    "Unique Identifier": "00008150-0000000000000001", "iTunes Version": "12.0",
}
with open(os.path.join(dest, "Info.plist"), "wb") as fh:
    plistlib.dump(info, fh)

manifest = {"IsEncrypted": encrypted, "Version": "10.0", "Date": None, "SystemDomainsVersion": "24.0"}
manifest.pop("Date")
if passcode != "missing":
    manifest["WasPasscodeSet"] = (passcode == "true")
if "--no-encflag" in sys.argv:
    manifest.pop("IsEncrypted")
if "--no-plist" not in sys.argv:
    with open(os.path.join(dest, "Manifest.plist"), "wb") as fh:
        if "--bad-plist" in sys.argv:
            fh.write(b"this is not a property list \x00\xff")
        elif "--list-plist" in sys.argv:
            plistlib.dump(["IsEncrypted", "WasPasscodeSet"], fh)
        else:
            plistlib.dump(manifest, fh)

with open(os.path.join(dest, "Status.plist"), "wb") as fh:
    plistlib.dump({"IsFullBackup": True, "SnapshotState": "finished", "Version": "3.3"}, fh)

db = os.path.join(dest, "Manifest.db")
if os.path.exists(db):
    os.remove(db)
if "--no-db" in sys.argv:
    sys.exit(0)
if encrypted:
    with open(db, "wb") as fh:
        fh.write(os.urandom(4096))          # ciphertext, not a SQLite file
else:
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE Files (fileID TEXT PRIMARY KEY, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)")
    rows = [("aa11", "HomeDomain", "Library/Preferences/com.apple.springboard.plist", 1, None),
            ("bb22", "HomeDomain", "Library/SMS/sms.db", 1, None),
            ("cc33", "CameraRollDomain", "Media/DCIM/100APPLE/IMG_0001.JPG", 1, None)]
    if evil:
        rows.append(("dd44", "HomeDomain", "Library/Caches/evil.db", 1, None))
    con.executemany("INSERT INTO Files VALUES (?,?,?,?,?)", rows)
    con.commit()
    con.close()
    if "--incomplete" not in sys.argv:
        for row in rows:
            if "--partial" in sys.argv and row[0] == "cc33":
                continue
            sub = os.path.join(dest, row[0][:2])
            os.makedirs(sub, exist_ok=True)
            open(os.path.join(sub, row[0]), "wb").close()
