"""File carving: recover files by magic headers/footers from raw bytes.

Recovers deleted media (photos, videos) that still linger in unallocated
sectors after deletion — the filesystem entry is gone, but the bytes remain
until overwritten.
"""
import os
import struct

JPEG_HDR = b"\xff\xd8\xff"
JPEG_FTR = b"\xff\xd9"
PNG_HDR = b"\x89PNG\r\n\x1a\n"
PNG_IEND = b"\x00\x00\x00\x00IEND\xaeB\x60\x82"
SQLITE_HDR = b"SQLite format 3\x00"
MP4_FTYP = b"ftyp"

# Safety caps so a missing footer can't emit a terabyte-sized "file".
MAX_FILE = 512 * 1024 * 1024


def _carve_jpeg(data, start):
    end = data.find(JPEG_FTR, start + 3)
    if end == -1:
        return None
    end += len(JPEG_FTR)
    if end - start > MAX_FILE or end - start < 128:
        return None
    return ("jpg", start, end - start)


def _carve_png(data, start):
    end = data.find(PNG_IEND, start + 8)
    if end == -1:
        return None
    end += len(PNG_IEND)
    if end - start > MAX_FILE or end - start < 64:
        return None
    return ("png", start, end - start)


def _carve_sqlite(data, start):
    # SQLite header: bytes 16-17 = page size (1 means 65536), bytes 28-31 =
    # size of DB in pages. Gives an exact carve length.
    if len(data) < start + 100:
        return None
    hdr = data[start:start + 100]
    page_size = struct.unpack(">H", hdr[16:18])[0] or 65536
    page_count = struct.unpack(">I", hdr[28:32])[0]
    if page_count == 0 or page_count > 1_000_000:
        return None
    total = page_size * page_count
    if total > MAX_FILE or total < page_size:
        return None
    return ("db", start, total)


def _carve_mp4(data, start):
    # 'ftyp' sits at offset 4 inside its box; box size is the 4 bytes before it.
    if start < 4:
        return None
    box_size = struct.unpack(">I", data[start - 4:start])[0]
    if box_size < 8 or box_size > 10 * 1024 * 1024:
        return None
    # Walk forward: extend through following boxes until we hit another ftyp
    # (next file) or the cap. Conservative but effective for carving.
    pos = start - 4 + box_size
    limit = min(len(data), start + MAX_FILE)
    while pos + 8 <= limit:
        nxt = struct.unpack(">I", data[pos:pos + 4])[0]
        typ = data[pos + 4:pos + 8]
        if typ == MP4_FTYP or nxt < 8 or nxt > 256 * 1024 * 1024:
            break
        pos += nxt
    total = pos - (start - 4)
    if total < 1024:
        return None
    return ("mp4", start - 4, total)


CARVERS = [
    (JPEG_HDR, _carve_jpeg),
    (PNG_HDR, _carve_png),
    (SQLITE_HDR, _carve_sqlite),
    (MP4_FTYP, _carve_mp4),
]


def carve_bytes(data, base_offset=0):
    """Scan one byte buffer; return list of (type, abs_offset, size)."""
    found = []
    claimed = []  # (start, end) ranges already assigned, to avoid nesting
    for magic, fn in CARVERS:
        pos = 0
        while True:
            i = data.find(magic, pos)
            if i == -1:
                break
            pos = i + 1
            abs_start = base_offset + i
            # skip if inside an already-carved file (except ftyp scan, which
            # legitimately appears inside mp4s — handled by claimed check below)
            if any(s <= abs_start < e for s, e in claimed):
                continue
            r = fn(data, i)
            if r:
                ext, s, size = r[0], base_offset + r[1], r[2]
                # re-check overlap with final coordinates
                if any(s < e and s + size > os_ for os_, e in claimed):
                    continue
                found.append((ext, s, size))
                claimed.append((s, s + size))
    found.sort(key=lambda t: t[1])
    return found


def carve_image(reader, out_dir, progress=None):
    """Carve a whole SectorReader image; write files; return manifest list."""
    os.makedirs(out_dir, exist_ok=True)
    manifest = []
    seen_starts = set()
    for chunk_off, chunk in reader.iter_chunks():
        for ext, abs_off, size in carve_bytes(chunk, chunk_off):
            if abs_off in seen_starts:
                continue
            seen_starts.add(abs_off)
            # re-read exact bytes from the image (chunk overlap may truncate)
            blob = reader.read_range(abs_off, size)
            name = "carved_%010d.%s" % (abs_off, ext)
            with open(os.path.join(out_dir, name), "wb") as f:
                f.write(blob)
            manifest.append({"type": ext, "offset": abs_off, "size": size,
                             "file": name})
            if progress:
                progress(len(manifest))
    return manifest
