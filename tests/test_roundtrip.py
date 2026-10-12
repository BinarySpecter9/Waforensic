"""Synthetic round-trip tests: carve, decrypt, parse, exif."""
import io
import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from waforensic.disk import SectorReader
from waforensic.carver import carve_image
from waforensic import crypt
from waforensic.db import connect_ro, get_messages, recover_deleted_fragments
from waforensic.exif import extract_exif


def make_jpeg():
    from PIL import Image
    buf = io.BytesIO()
    Image.new("RGB", (64, 64), (200, 30, 30)).save(buf, "JPEG")
    return buf.getvalue()


def make_png():
    from PIL import Image
    buf = io.BytesIO()
    Image.new("RGB", (32, 32), (30, 200, 30)).save(buf, "PNG")
    return buf.getvalue()


def make_test_db(path):
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE messages (_id INTEGER PRIMARY KEY, key_remote_jid TEXT,"
                 " key_from_me INTEGER, timestamp INTEGER, data TEXT)")
    conn.execute("INSERT INTO messages VALUES (1,'12345@s.whatsapp.net',1,1700000000000,'hello test')")
    conn.execute("INSERT INTO messages VALUES (2,'12345@s.whatsapp.net',0,1700000001000,'reply here')")
    conn.commit()
    conn.close()
    with open(path, "rb") as f:
        return f.read()


def test_carve():
    d = tempfile.mkdtemp()
    img = os.path.join(d, "test.img")
    jpeg, png = make_jpeg(), make_png()
    dbp = os.path.join(d, "t.db")
    db_blob = make_test_db(dbp)
    blob = (os.urandom(700) + jpeg + os.urandom(1500) + png +
            os.urandom(3000) + db_blob + os.urandom(500))
    # pad to sector multiple
    blob += b"\x00" * (512 - len(blob) % 512)
    with open(img, "wb") as f:
        f.write(blob)
    with SectorReader(img) as r:
        man = carve_image(r, os.path.join(d, "out"))
    types = sorted(m["type"] for m in man)
    assert "jpg" in types, "jpeg not carved: %s" % types
    assert "png" in types, "png not carved: %s" % types
    assert "db" in types, "sqlite not carved: %s" % types
    # verify carved jpeg opens
    from PIL import Image
    jm = next(m for m in man if m["type"] == "jpg")
    Image.open(os.path.join(d, "out", jm["file"])).verify()
    print("carve: OK (%s)" % types)


def test_crypt_roundtrip():
    key = os.urandom(32)
    d = tempfile.mkdtemp()
    dbp = os.path.join(d, "t.db")
    original = make_test_db(dbp)
    for builder, label in ((crypt.build_test_crypt14, "protobuf-header"),
                           (crypt.build_test_crypt14_fallback, "fallback-offsets")):
        enc = builder(original, key)
        dec = crypt.decrypt(enc, key)
        assert dec == original, "round-trip mismatch (%s)" % label
        print("crypt [%s]: OK" % label)
    # wrong key must fail
    try:
        crypt.decrypt(enc, os.urandom(32))
        raise AssertionError("wrong key should fail")
    except ValueError:
        pass
    # key file loading (158-byte layout, key at 126)
    kf = os.path.join(d, "key")
    with open(kf, "wb") as f:
        f.write(os.urandom(126) + key)
    assert crypt.load_key(kf) == key
    assert crypt.load_key(key.hex()) == key
    print("crypt: OK (round-trip + wrong-key rejection + key loading)")


def test_crypt_realistic_headers():
    """Real 2.26-style BackupPrefix headers: nested IV + header != 122 bytes.

    The legacy IV@8/data@122 guesses must FAIL on these (proving the new
    protobuf walk is what decrypts them), while decrypt() succeeds."""
    key = os.urandom(32)
    d = tempfile.mkdtemp()
    dbp = os.path.join(d, "t.db")
    original = make_test_db(dbp)
    for builder, label in ((crypt.build_test_crypt15_realistic, "crypt15-nested"),
                           (crypt.build_test_crypt14_realistic, "crypt14-nested")):
        enc = builder(original, key)
        # legacy guesses must fail on a realistic header
        try:
            crypt._gcm_decrypt(key, enc[8:24], enc[122:])
            raise AssertionError("legacy IV@8/data@122 unexpectedly worked (%s)" % label)
        except AssertionError:
            raise
        except Exception:
            pass  # expected: auth fails
        dec = crypt.decrypt(enc, key)
        assert dec == original, "round-trip mismatch (%s)" % label
        print("crypt [%s realistic header]: OK" % label)


def test_crypt_key_repair():
    """A single wrong hex digit in a typed key must be repaired automatically."""
    key = os.urandom(32)
    khex = key.hex()
    d = tempfile.mkdtemp()
    dbp = os.path.join(d, "t.db")
    original = make_test_db(dbp)
    enc = crypt.build_test_crypt15_realistic(original, key)
    p = os.path.join(d, "m.crypt15")
    o = os.path.join(d, "m.db")
    with open(p, "wb") as f:
        f.write(enc)
    bad = khex[:10] + ("0" if khex[10] != "0" else "1") + khex[11:]
    assert bad != khex and len(bad) == 64
    crypt.decrypt_file(p, bad, o)  # repair path
    with open(o, "rb") as f:
        assert f.read() == original, "repaired key gave wrong plaintext"
    # a fully wrong typed key must still fail loudly
    try:
        crypt.decrypt_file(p, os.urandom(32).hex(), o)
        raise AssertionError("fully wrong key should fail")
    except ValueError:
        pass
    print("crypt [key repair]: OK")


def test_db_parse():
    d = tempfile.mkdtemp()
    dbp = os.path.join(d, "t.db")
    make_test_db(dbp)
    conn = connect_ro(dbp)
    msgs = get_messages(conn, limit=10)
    assert len(msgs) == 2 and msgs[0]["text"] == "reply here", msgs
    frags = recover_deleted_fragments(dbp)  # should not crash on live db
    assert isinstance(frags, list)
    print("db: OK (%d messages, fragment scan ran)" % len(msgs))


def test_exif():
    from PIL import Image
    d = tempfile.mkdtemp()
    p = os.path.join(d, "g.jpg")
    img = Image.new("RGB", (32, 32), (0, 0, 200))
    ex = img.getexif()
    ex[271], ex[272] = "TestMake", "TestModel"  # Make, Model
    img.save(p, "JPEG", exif=ex)
    got = extract_exif(p)
    assert got.get("Make") == "TestMake", got
    print("exif: OK")


if __name__ == "__main__":
    test_carve()
    test_crypt_roundtrip()
    test_crypt_realistic_headers()
    test_crypt_key_repair()
    test_db_parse()
    test_exif()
    print("ALL TESTS PASSED")
