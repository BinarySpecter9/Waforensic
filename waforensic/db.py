"""WhatsApp msgstore.db parsing + deleted-record recovery.

Handles both the legacy schema (messages / chat_list / wa_contacts tables) and
the current schema (message / chat / jid / message_media tables).

Deleted-record recovery: SQLite keeps deleted content in freelist pages and in
unallocated space inside b-tree leaf pages until it is overwritten. This module
scans those regions and attempts to parse leftover records heuristically.
Recovered fragments are labeled as such — treat them as leads, not evidence.
"""
import os
import sqlite3
import struct


def connect_ro(path):
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    return sqlite3.connect("file:%s?mode=ro" % path, uri=True)


def _tables(conn):
    return {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}


def get_chats(conn):
    t = _tables(conn)
    if "chat" in t:  # current schema
        q = ("SELECT c._id, j.raw_string, c.subject FROM chat c "
             "LEFT JOIN jid j ON j._id = c.jid_row_id")
        return [{"id": r[0], "jid": r[1], "subject": r[2]}
                for r in conn.execute(q)]
    if "chat_list" in t:  # legacy schema
        return [{"id": r[0], "jid": r[1], "subject": None}
                for r in conn.execute("SELECT _id, key_remote_jid FROM chat_list")]
    return []


def get_messages(conn, limit=1000):
    """Return newest-first message dicts across both schemas."""
    t = _tables(conn)
    out = []
    if "message" in t:  # current schema
        cols = {r[1] for r in conn.execute("PRAGMA table_info(message)")}
        text_col = "text_data" if "text_data" in cols else None
        q = ("SELECT m._id, j.raw_string, m.from_me, m.timestamp, "
             + (("m." + text_col) if text_col else "NULL") +
             ", m.message_type FROM message m "
             "LEFT JOIN chat c ON c._id = m.chat_row_id "
             "LEFT JOIN jid j ON j._id = c.jid_row_id "
             "ORDER BY m.timestamp DESC LIMIT %d" % int(limit))
        for r in conn.execute(q):
            out.append({"id": r[0], "chat": r[1], "from_me": bool(r[2]),
                        "timestamp": r[3], "text": r[4], "type": r[5]})
        return out
    if "messages" in t:  # legacy schema
        cols = {r[1] for r in conn.execute("PRAGMA table_info(messages)")}
        sel = ["_id", "key_remote_jid", "key_from_me", "timestamp", "data"]
        sel += ["media_mime_type"] if "media_mime_type" in cols else ["NULL"]
        sel += ["media_url"] if "media_url" in cols else ["NULL"]
        q = ("SELECT %s FROM messages ORDER BY timestamp DESC LIMIT %d"
             % (", ".join(sel), int(limit)))
        for r in conn.execute(q):
            out.append({"id": r[0], "chat": r[1], "from_me": bool(r[2]),
                        "timestamp": r[3], "text": r[4],
                        "media_mime": r[5], "media_url": r[6]})
        return out
    return []


# ---- low-level SQLite page parsing for deleted-record recovery ----

def _read_varint(buf, pos):
    result, shift = 0, 0
    while pos < len(buf):
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, pos
        shift += 7
    return None, pos


def _try_parse_record(buf):
    """Heuristic: does buf look like a SQLite record with some text?"""
    if len(buf) < 8:
        return None
    hlen, p = _read_varint(buf, 0)
    if hlen is None or hlen < 2 or hlen > len(buf) or hlen > 200:
        return None
    # walk the serial-type array
    types = []
    while p < hlen:
        st, p = _read_varint(buf, p)
        if st is None:
            return None
        types.append(st)
    body = buf[hlen:]
    texts = []
    for st in types:
        if st == 0:
            continue
        if st == 1:
            ln, body = 1, body[1:]
        elif st >= 13 and st % 2 == 1:  # TEXT
            ln = (st - 13) // 2
            if ln > len(body) or ln > 4000:
                return None
            try:
                texts.append(body[:ln].decode("utf-8", "replace"))
            except Exception:  # noqa: BLE001
                return None
            body = body[ln:]
        elif st >= 12 and st % 2 == 0:  # BLOB
            ln = (st - 12) // 2
            if ln > len(body):
                return None
            body = body[ln:]
        else:  # ints/floats: fixed sizes
            ln = {2: 2, 3: 3, 4: 4, 5: 6, 6: 8, 7: 8, 8: 0, 9: 0}.get(st, None)
            if ln is None or ln > len(body):
                return None
            body = body[ln:]
    joined = " ".join(t for t in texts if t.strip())
    if len(joined) >= 4 and any(c.isalnum() for c in joined):
        return joined
    return None


def recover_deleted_fragments(path, max_hits=200):
    """Scan unallocated areas of b-tree leaf pages for leftover records.

    Returns [{'page': n, 'offset': o, 'text': fragment}]. Heuristic — every hit
    needs human review; false positives are expected.
    """
    with open(path, "rb") as f:
        blob = f.read()
    if not blob.startswith(b"SQLite format 3\x00"):
        raise ValueError("not a SQLite database")
    page_size = struct.unpack(">H", blob[16:18])[0] or 65536
    hits = []
    for pno in range(1, len(blob) // page_size + 1):
        base = (pno - 1) * page_size
        page = blob[base:base + page_size]
        off = 100 if pno == 1 else 0  # page 1 has the 100-byte db header
        if off + 8 > len(page):
            continue
        ptype = page[off]
        if ptype != 0x0D:  # table b-tree leaf only
            continue
        ncells = struct.unpack(">H", page[off + 3:off + 5])[0]
        content = struct.unpack(">H", page[off + 5:off + 7])[0] or 65536
        ptr_end = off + 8 + ncells * 2
        gap_start, gap_end = ptr_end, off + content
        if gap_end - gap_start < 16:
            continue
        gap = page[gap_start:gap_end]
        # slide a window; try record parse at each position
        for i in range(0, len(gap) - 16, 4):
            frag = _try_parse_record(gap[i:i + 512])
            if frag and len(hits) < max_hits:
                hits.append({"page": pno, "offset": base + gap_start + i,
                             "text": frag[:300]})
    # de-dup overlapping hits
    seen, uniq = set(), []
    for h in hits:
        key = h["text"][:60]
        if key not in seen:
            seen.add(key)
            uniq.append(h)
    return uniq
