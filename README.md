# WAForensic — Android & WhatsApp Forensic Recovery Engine

Offline, private data-recovery toolkit for Android devices. Everything runs
locally on your computer — nothing is uploaded, transmitted, or stored on any
server. Ever.

## What it does

- **Deep storage acquisition** — pull WhatsApp data over USB via `adb`
  (works with USB debugging enabled, device unlocked); optional block-level
  `dd` dump on rooted devices to scan beyond what the file manager shows.
- **WhatsApp media recovery** — carve deleted photos, videos, voice notes,
  documents and stickers from raw disk images by file signature, even after
  the filesystem entry is gone. Supports WhatsApp & WhatsApp Business.
- **Native database decryption** — decrypt `msgstore.db.crypt12/.crypt14/
  .crypt15` backups with AES-256-GCM using your device key file.
- **Database analysis** — parse chats and messages from `msgstore.db`
  (legacy and current schemas), plus heuristic recovery of deleted-record
  fragments lingering in SQLite freelist/unallocated space.
- **Photo EXIF & GPS extraction** — hidden camera details, timestamps, and
  coordinates from any photo.
- **Interactive master report** — auto-generated HTML report summarizing
  every recovered file with timestamps and metadata.

## Honest limitations

- Cannot recover data after a full factory reset (hardware file-based
  encryption on Android 10+ wipes the keys).
- Cannot bypass screen locks, PINs, passwords, or biometrics — the device
  must be unlocked with USB debugging enabled.
- Android only. No iPhone/iOS support.
- Cannot guarantee recovery of files overwritten by system activity.
- Cannot decrypt WhatsApp backups without the valid 158-byte key file
  (or 64-digit key for E2E backups). There is no key recovery.

## Install

    pip install cryptography pillow
    # Android acquisition also needs: adb (Android platform-tools)

## Usage

    # 1. Pull WhatsApp data from a USB-connected phone
    python -m waforensic.cli acquire --app whatsapp -o case1
    python -m waforensic.cli acquire --app business --deep -o case1   # needs root

    # 2. Carve deleted files from a raw image
    python -m waforensic.cli carve mmcblk0.img -o case1/carved

    # 3. Decrypt a backup (key from YOUR device: /data/data/com.whatsapp/files/key)
    python -m waforensic.cli decrypt msgstore.db.crypt14 key -o msgstore.db

    # 4. Parse chats + hunt deleted fragments
    python -m waforensic.cli db msgstore.db --recover-deleted -o messages.json

    # 5. EXIF/GPS on recovered photos
    python -m waforensic.cli exif case1/carved/carved_*.jpg

    # 6. Master HTML report
    python -m waforensic.cli report --manifest case1/carved/manifest.json \
        --db-json messages.json -o case1/report.html

## Format notes

- crypt12: IV (16 B) at offset 51, ciphertext from 67, zlib-compressed payload.
- crypt14/15: 122-byte header with the IV as a protobuf field (usually at
  offset 8); the engine scans for the IV and validates candidate offsets with
  GCM authentication, so wrong guesses fail loudly instead of silently.
- Key file: 158 bytes, AES-256 key at offset 126.
- References: `wa-crypt-tools` / WhatsApp-Crypt14-Decrypter (offset behavior),
  public msgstore schema research.

## Authorized use only

This tool is for recovering **your own data**, or data you have explicit
consent or legal authority to examine (e.g. device owners, IT admins,
licensed investigators). Do not use it on someone else's device or account
without their knowledge and permission — in most places that is illegal.
The authors accept no liability for misuse.
