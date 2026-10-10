"""EXIF & GPS metadata extraction from photos.

Recovers hidden camera details, timestamps, and coordinates — the metadata
most people don't know their photos carry.
"""
from PIL.ExifTags import GPSTAGS, TAGS


def _dms_to_decimal(dms, ref):
    """EXIF GPS stores degrees/minutes/seconds as rationals."""
    def f(x):
        try:
            return float(x)
        except (TypeError, ValueError):
            return float(x.numerator) / float(x.denominator)
    d, m, s = (f(v) for v in dms)
    dec = d + m / 60 + s / 3600
    if ref in ("S", "W"):
        dec = -dec
    return dec


def extract_exif(path):
    """Return dict of human-readable EXIF tags; {} if none/unreadable."""
    from PIL import Image
    try:
        img = Image.open(path)
        raw = img.getexif()
    except Exception:
        return {}
    out = {}
    for tag_id, val in raw.items():
        name = TAGS.get(tag_id, tag_id)
        if name == "GPSInfo":
            gps = {}
            for k, v in val.items():
                gps[GPSTAGS.get(k, k)] = v
            try:
                lat = _dms_to_decimal(gps["GPSLatitude"], gps["GPSLatitudeRef"])
                lon = _dms_to_decimal(gps["GPSLongitude"], gps["GPSLongitudeRef"])
                out["GPS"] = {"latitude": lat, "longitude": lon,
                              "maps": "https://maps.google.com/?q=%s,%s" % (lat, lon)}
            except (KeyError, TypeError, ValueError):
                out["GPS_raw"] = {k: str(v) for k, v in gps.items()}
        else:
            out[name] = str(val)[:200]
    return out


def summarize(path):
    ex = extract_exif(path)
    keep = {k: ex[k] for k in ("Make", "Model", "DateTime", "DateTimeOriginal",
                               "GPS", "ImageWidth", "ImageLength") if k in ex}
    return keep
