"""WhatsApp backup decryption (msgstore.db.crypt12 / .crypt14 / .crypt15).

Format notes (public research; see README for sources):
- All three formats use AES-256-GCM.
- The device key file is 158 bytes; the AES key is the 32 bytes at offset 126.
  On a rooted device it lives at /data/data/com.whatsapp/files/key
  (crypt15 E2E backups use encrypted_backup.key / a 64-digit key instead).
- crypt12: 16-byte IV at file offset 51, ciphertext from offset 67, the
  decrypted payload is zlib-compressed.
- crypt14/15: the file opens with a protobuf-encoded header that carries the
  16-byte IV; ciphertext follows the header, GCM tag is the last 16 bytes.
  wa-crypt-tools falls back to IV@8 / data@122 when protobuf parsing fails.

You must supply the key from a device/backup you own or are authorized to
examine. There is no key recovery here — without the key, decryption is
computationally infeasible, by design.
"""
import os
import zlib

SQLITE_MAGIC = b"SQLite format 3\x00"
ZLIB_MAGIC = b"\x78"


def load_key(key):
    """Accept a path to the 158-byte key file, or a 64-char hex key string."""
    if len(key) == 64 and all(c in "0123456789abcdefABCDEF" for c in key):
        return bytes.fromhex(key)
    if os.path.isfile(key):
        with open(key, "rb") as f:
            blob = f.read()
        if len(blob) == 158:
            return blob[126:158]
        if len(blob) == 32:
            return blob
        raise ValueError("key file is %d bytes; expected 158 (device key) or 32 (raw)" % len(blob))
    raise ValueError("key must be a 64-char hex string or a path to a key file")


def _read_varint(buf, pos):
    result, shift = 0, 0
    while pos < len(buf):
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, pos
        shift += 7
        if shift > 64:
            return None, pos
    return None, pos


def find_iv_in_header(header):
    """Minimal protobuf scan: look for a length-delimited field that is
    exactly 16 bytes long (the GCM IV). Returns (iv, data_offset) or None."""
    pos, end = 0, min(len(header), 512)
    while pos < end:
        tag, pos = _read_varint(header, pos)
        if tag is None:
            break
        field_no, wire = tag >> 3, tag & 0x07
        if wire == 2:  # length-delimited
            ln, pos = _read_varint(header, pos)
            if ln is None or pos + ln > len(header):
                break
            if ln == 16 and field_no:  # plausible IV
                return header[pos:pos + 16], pos + 16
            pos += ln
        elif wire == 0:
            _, pos = _read_varint(header, pos)
        elif wire in (1, 5):
            pos += 8 if wire == 1 else 4
        else:
            break
    return None


def _gcm_decrypt(key, iv, blob):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    # blob = ciphertext || 16-byte tag
    return AESGCM(key).decrypt(iv, blob, None)


def _maybe_zlib(payload):
    if payload[:1] == ZLIB_MAGIC:
        try:
            return zlib.decompress(payload)
        except zlib.error:
            return payload
    return payload


def decrypt_crypt14(data, key):
    """crypt14/crypt15 layout: 122-byte header carrying the IV as a protobuf
    field (commonly at offset 8), then ciphertext || 16-byte GCM tag.

    Tries candidate (IV, data-offset) pairs; AES-GCM authentication rejects
    wrong guesses loudly, so only a correct guess can return."""
    header = data[:512]
    found = find_iv_in_header(header)
    candidates = []
    if found:
        iv, iv_end = found
        candidates.append((iv, 122))          # documented header length
        if iv_end != 122:
            candidates.append((iv, iv_end))  # IV field was last in header
    candidates.append((data[8:24], 122))     # documented fallback offsets
    errors = []
    for iv, data_off in candidates:
        if len(iv) != 16 or not (0 < data_off < len(data)):
            continue
        try:
            pt = _gcm_decrypt(key, iv, data[data_off:])
        except Exception as e:  # noqa: BLE001 - wrong guess, try next
            errors.append("data@%d: %s" % (data_off, type(e).__name__))
            continue
        out = _maybe_zlib(pt)
        if out.startswith(SQLITE_MAGIC):
            return out
        errors.append("data@%d: bad offsets or wrong key (no SQLite magic)" % data_off)
    raise ValueError("crypt14/15: " + "; ".join(errors) if errors else "crypt14/15: no candidates")


def decrypt_crypt12(data, key):
    iv, ct = data[51:67], data[67:]
    if len(iv) != 16:
        raise ValueError("file too short for crypt12 layout")
    pt = _gcm_decrypt(key, iv, ct)
    out = _maybe_zlib(pt)
    if not out.startswith(SQLITE_MAGIC):
        # some variants are not compressed
        return pt
    return out


def decrypt(data, key):
    """Auto-detect crypt12 vs crypt14/15; return plaintext.

    Raises ValueError if nothing verifies (wrong key or corrupt file).
    """
    errors = []
    for name, fn in (("crypt14/15", decrypt_crypt14), ("crypt12", decrypt_crypt12)):
        try:
            out = fn(data, key)
        except Exception as e:  # noqa: BLE001 - trying next layout
            errors.append("%s: %s %s" % (name, type(e).__name__, e))
            continue
        if out.startswith(SQLITE_MAGIC):
            return out
        errors.append("%s: decrypted but no SQLite magic" % name)
    raise ValueError("decryption failed — " + "; ".join(errors))


def decrypt_file(enc_path, key, out_path):
    with open(enc_path, "rb") as f:
        data = f.read()
    aes_key = load_key(key)
    plain = decrypt(data, aes_key)
    with open(out_path, "wb") as f:
        f.write(plain)
    return out_path


# ---- test helpers: build synthetic crypt files in the documented layouts ----
def build_test_crypt14(plaintext, key):
    """crypt14-layout blob: 122-byte header with the IV as a protobuf field at
    offset 8 (mirrors the documented real layout)."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import os as _os
    iv = _os.urandom(16)
    header = b"\x00" * 8 + b"\x0a\x10" + iv + b"\x00" * (122 - 8 - 18)
    assert len(header) == 122
    ct = AESGCM(key).encrypt(iv, zlib.compress(plaintext), None)
    return header + ct


def build_test_crypt14_fallback(plaintext, key):
    """crypt14-layout blob with an unparseable header: exercises the documented
    fallback offsets (IV@8, data@122)."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import os as _os
    iv = _os.urandom(16)
    header = b"\x0f" + b"\x00" * 7 + iv + b"\x00" * (122 - 24)
    ct = AESGCM(key).encrypt(iv, zlib.compress(plaintext), None)
    return header + ct
