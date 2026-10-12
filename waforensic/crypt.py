"""WhatsApp backup decryption (msgstore.db.crypt12 / .crypt14 / .crypt15).

Format notes (public research; header schema read out of com.whatsapp 2.26.34.7
and mirrored by wa-crypt-tools, GPL-3.0):
- All three formats use AES-256-GCM; the GCM tag is the last 16 bytes of the file.
- crypt12: 16-byte IV at file offset 51, ciphertext from offset 67, the
  decrypted payload is zlib-compressed. Key = 32 bytes at offset 126 of the
  158-byte device key file.
- crypt14/15: the file opens with a BackupPrefix protobuf message, then the
  ciphertext. BackupPrefix fields (WhatsApp's own names):
      1 key_type_deprecated            (varint)
      2 wa_provided_key_data           -> C14_cipher{ key_version=2,
                                          server_salt=3, google_id_salt=4,
                                          encryption_iv=5 }      (crypt14)
      3 e2ee_key_data                  -> C15_IV{ encryption_iv=1 } (crypt15)
      4 backup_metadata                -> BackupExpiry{...}       (bytes)
      5 passkey_encryption_metadata    (bytes)
      6 key_type_new                   (varint; 2.26 crypt15 = E2EE_ENCRYPTION_KEY)
  The 16-byte encryption IV lives NESTED inside field 2 or 3 -- a flat scan of
  the top level cannot see it, and the header is usually longer than the old
  documented 122 bytes, so fixed IV@8 / data@122 guesses fail on real files.
  The header end is found by walking the protobuf fields; AES-GCM
  authentication is the final oracle, so only a correct (IV, offset) pair can
  ever return data.
- crypt15 key: the 64-digit backup key shown by WhatsApp (or the
  encrypted_backup.key file) is used directly as the AES-256 key. Typed keys
  get single-digit near-miss repair (a wrong digit fails auth exactly like a
  wrong key); key files are never second-guessed.

You must supply the key from a device/backup you own or are authorized to
examine. There is no key recovery here -- without the (near-)correct key,
decryption is computationally infeasible, by design.
"""
import os
import zlib

SQLITE_MAGIC = b"SQLite format 3\x00"
ZLIB_MAGIC = b"\x78"
_HEX = set("0123456789abcdefABCDEF")


def load_key(key):
    """Accept a path to the 158-byte key file, or a 64-char hex key string."""
    if len(key) == 64 and all(c in _HEX for c in key):
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


# ---------------------------------------------------------------------------
# BackupPrefix protobuf walk (crypt14/15)
# ---------------------------------------------------------------------------

# Known BackupPrefix fields -> expected wire type (0 = varint, 2 = bytes).
# Unknown fields are still skipped (wire 0/2 only) so the walk survives
# schema additions; fixed-width/group wire types stop the walk.
_PREFIX_KNOWN = {1: 0, 2: 2, 3: 2, 4: 2, 5: 2, 6: 0}
_C14_CIPHER_IV_FIELD = 5   # C14_cipher.encryption_iv
_C15_IV_FIELD = 1          # C15_IV.encryption_iv
_C14_INNER = {2: 2, 3: 2, 4: 2, 5: 2}  # C14_cipher fields
_C15_INNER = {1: 2}                    # C15_IV fields


def _walk_fields(buf, start, max_len, schema):
    """Yield (field_no, wire, payload_bytes_or_None, field_end) for each
    protobuf field parsed from buf[start:], stopping at the first byte that
    does not look like a field. `schema` maps known field numbers to their
    wire type; unknown field numbers are still accepted (and skipped) when
    their wire type is varint or length-delimited, so the walk survives
    schema additions. Fixed-width/group wire types stop the walk."""
    pos, end = start, min(len(buf), start + max_len)
    while pos < end:
        tag, p = _read_varint(buf, pos)
        if tag is None:
            return
        field_no, wire = tag >> 3, tag & 0x07
        if field_no in schema:
            if schema[field_no] != wire:
                return
        elif wire not in (0, 2):
            return
        if wire == 0:
            val, p2 = _read_varint(buf, p)
            if val is None:
                return
            yield field_no, wire, None, p2
            pos = p2
        else:  # wire == 2
            ln, p2 = _read_varint(buf, p)
            if ln is None or p2 + ln > len(buf):
                return
            yield field_no, wire, buf[p2:p2 + ln], p2 + ln
            pos = p2 + ln


def _nested_iv(payload, want_field, schema):
    """Find the 16-byte encryption IV inside a nested cipher message
    (C14_cipher or C15_IV payload)."""
    if not payload:
        return None
    first16 = None
    for f_no, wire, blob, _end in _walk_fields(payload, 0, len(payload), schema):
        if wire == 2 and len(blob) == 16:
            if first16 is None:
                first16 = blob
            if f_no == want_field:
                return bytes(blob)
    return bytes(first16) if first16 is not None else None


def _parse_backup_prefix(data):
    """Parse the BackupPrefix header at the start of a crypt14/15 file.

    Returns (iv, header_ends): iv is the 16-byte encryption IV extracted from
    the nested field 2 (crypt14) / field 3 (crypt15) cipher message, or None;
    header_ends lists the offset where each successfully parsed top-level
    field ended -- the ciphertext starts at one of them."""
    iv, header_ends = None, []
    for field_no, wire, blob, field_end in _walk_fields(data, 0, 1024, _PREFIX_KNOWN):
        header_ends.append(field_end)
        if iv is None and wire == 2 and field_no == 2:
            iv = _nested_iv(blob, _C14_CIPHER_IV_FIELD, _C14_INNER)
        elif iv is None and wire == 2 and field_no == 3:
            iv = _nested_iv(blob, _C15_IV_FIELD, _C15_INNER)
    return iv, header_ends


def _header_candidates(data):
    """Ordered (iv, data_offset, label) candidates for crypt14/15.

    AES-GCM authentication is the oracle: only a correct pair decrypts, so
    extra candidates cost time but can never produce a false positive."""
    nested_iv, header_ends = _parse_backup_prefix(data)
    ends = sorted(set(header_ends), reverse=True)
    cands, seen = [], set()

    def add(ivv, off, label):
        if ivv is None or len(ivv) != 16:
            return
        if not (0 < off <= len(data) - 16):
            return
        k = (bytes(ivv), off)
        if k not in seen:
            seen.add(k)
            cands.append((bytes(ivv), off, label))

    for off in ends + [122]:
        add(nested_iv, off, "nested-iv@header+%d" % off)
    flat = find_iv_in_header(data[:512])
    if flat:
        fiv, iv_end = flat
        for off in [122, iv_end] + ends:
            add(fiv, off, "flat-iv@%d" % off)
    for off in [122] + ends:
        add(data[8:24], off, "legacy-iv@8/data@%d" % off)
    return cands


def _gcm_decrypt(key, iv, blob):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    # blob = ciphertext || 16-byte tag
    return AESGCM(key).decrypt(iv, blob, None)


def _gcm_prefix(key, iv, ct_prefix):
    """Decrypt a ciphertext prefix WITHOUT verifying the tag (streaming GCM
    decrypts block by block; the tag is only checked at finalize). Used for
    cheap plaintext-magic checks, never as proof of correctness."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    d = Cipher(algorithms.AES(key), modes.GCM(iv)).decryptor()
    return d.update(ct_prefix)


def _maybe_zlib(payload):
    if payload[:1] == ZLIB_MAGIC:
        try:
            return zlib.decompress(payload)
        except zlib.error:
            return payload
    return payload


def _try_candidate(key, iv, off, data):
    """Full authenticated decrypt of one candidate; None on any failure."""
    try:
        pt = _gcm_decrypt(key, iv, data[off:])
    except Exception:  # noqa: BLE001 - wrong (iv, offset), try next
        return None
    out = _maybe_zlib(pt)
    return out if out.startswith(SQLITE_MAGIC) else None


def decrypt_crypt14(data, key):
    """crypt14/crypt15: BackupPrefix protobuf header carrying the IV nested
    inside field 2 (crypt14) / field 3 (crypt15), then ciphertext || tag.

    Tries candidate (IV, data-offset) pairs; AES-GCM authentication rejects
    wrong guesses loudly, so only a correct guess can return."""
    errors = []
    for iv, off, label in _header_candidates(data):
        out = _try_candidate(key, iv, off, data)
        if out is not None:
            return out
        errors.append("%s: auth failed" % label)
    raise ValueError("crypt14/15: " + "; ".join(errors) if errors else "crypt14/15: no candidates")


def _prefix_plausible(key, iv, off, data):
    """Cheap pre-check: decrypt 64 bytes (no tag verification) and look for
    backup plaintext magic. Filters key candidates; never accepts one."""
    try:
        pt = _gcm_prefix(key, iv, data[off:off + 64])
    except Exception:  # noqa: BLE001
        return False
    if pt.startswith(SQLITE_MAGIC):
        return True
    if len(pt) >= 2 and pt[:1] == ZLIB_MAGIC and pt[1:2] in (b"\x01", b"\x9c", b"\xda"):
        try:
            zlib.decompressobj().decompress(pt)
            return True
        except Exception:  # noqa: BLE001 - random bytes are not a deflate stream
            return False
    return False


def _near_miss_keys(key_hex):
    """All single-hex-digit substitutions plus adjacent transpositions of a
    typed 64-digit key -- the classic hand-copy slips."""
    h = key_hex.lower()
    out = []
    for i, ch in enumerate(h):
        for d in "0123456789abcdef":
            if d != ch:
                out.append(bytes.fromhex(h[:i] + d + h[i + 1:]))
    for i in range(len(h) - 1):
        if h[i] != h[i + 1]:
            out.append(bytes.fromhex(h[:i] + h[i + 1] + h[i] + h[i + 2:]))
    return out


def decrypt_with_repair(data, key_hex):
    """Try near-miss variants of a typed 64-digit key. A candidate is only
    accepted after a full authenticated decrypt, so a repaired key is as
    trustworthy as a typed-correct one."""
    cands = _header_candidates(data)
    tried = 0
    for k in _near_miss_keys(key_hex):
        tried += 1
        for iv, off, _label in cands:
            if _prefix_plausible(k, iv, off, data):
                out = _try_candidate(k, iv, off, data)
                if out is not None:
                    return out
    raise ValueError("crypt14/15: key repair tried %d near-miss keys, none decrypted" % tried)


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
    raise ValueError("decryption failed -- " + "; ".join(errors))


def _is_typed_hex(key):
    return isinstance(key, str) and len(key) == 64 and all(c in _HEX for c in key)


def decrypt_file(enc_path, key, out_path):
    with open(enc_path, "rb") as f:
        data = f.read()
    typed = _is_typed_hex(key)
    aes_key = load_key(key)
    try:
        plain = decrypt(data, aes_key)
    except ValueError:
        if not typed:
            raise
        # The key was typed by hand: one wrong digit fails auth exactly like
        # a wrong key. Repair it automatically before giving up.
        plain = decrypt_with_repair(data, key)
    with open(out_path, "wb") as f:
        f.write(plain)
    return out_path


# ---- test helpers: build synthetic crypt files in the documented layouts ----
def _enc_uvarint(v):
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def _pb_bytes(field_no, blob):
    return _enc_uvarint((field_no << 3) | 2) + _enc_uvarint(len(blob)) + blob


def _pb_varint(field_no, val):
    return _enc_uvarint((field_no << 3) | 0) + _enc_uvarint(val)


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


def build_test_crypt15_realistic(plaintext, key):
    """crypt15-layout blob mirroring a real 2.26 BackupPrefix header: the IV is
    nested as BackupPrefix.e2ee_key_data(field 3) -> C15_IV.encryption_iv
    (field 1), the header carries backup_metadata + key_type_new, is longer
    than 122 bytes, and has no leading field 1 -- so the legacy IV@8/data@122
    guesses fail on it."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import os as _os
    iv = _os.urandom(16)
    c15_iv = _pb_bytes(1, iv)                      # C15_IV{ encryption_iv }
    e2ee_key_data = _pb_bytes(3, c15_iv)           # BackupPrefix.e2ee_key_data
    meta = b"".join([
        _pb_bytes(1, b"2.26.34.7"),                 # app_version
        _pb_bytes(2, b"Pixel 8"),                   # device_model
        _pb_bytes(3, b"92"),                       # jid_suffix
        _pb_varint(4, 1),                          # backup_version
    ] + [_pb_varint(n, 1) for n in range(5, 38)] + [
        _pb_varint(38, 123456),                    # backup_export_file_size
    ])
    header = e2ee_key_data + _pb_bytes(4, meta) + _pb_varint(6, 4)
    assert len(header) > 122, len(header)
    assert header[8:24] != iv  # the legacy IV@8 guess must be wrong here
    ct = AESGCM(key).encrypt(iv, zlib.compress(plaintext), None)
    return header + ct


def build_test_crypt14_realistic(plaintext, key):
    """crypt14-layout blob mirroring a real BackupPrefix header: the IV is
    nested as BackupPrefix.wa_provided_key_data(field 2) ->
    C14_cipher.encryption_iv (field 5), alongside a decoy 16-byte
    google_id_salt (field 4) that a flat header scan would pick first."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import os as _os
    iv = _os.urandom(16)
    c14 = (_pb_bytes(2, b"1")                      # key_version
           + _pb_bytes(3, _os.urandom(32))          # server_salt
           + _pb_bytes(4, _os.urandom(16))          # google_id_salt (decoy)
           + _pb_bytes(5, iv))                      # encryption_iv
    meta = _pb_bytes(1, b"2.26.34.7") + _pb_bytes(3, b"92")
    header = _pb_bytes(2, c14) + _pb_bytes(4, meta)
    ct = AESGCM(key).encrypt(iv, zlib.compress(plaintext), None)
    return header + ct
