"""HTML case report builder."""
import html
import json
import os
from datetime import datetime


def _esc(s):
    return html.escape(str(s))


def build_report(findings, out_path, case_name="WAForensic case"):
    """findings: dict with keys 'carved' (list), 'messages' (list),
    'deleted_fragments' (list), 'notes' (list of str)."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    parts = ["<html><head><meta charset='utf-8'><title>%s</title>" % _esc(case_name),
             "<style>body{font-family:sans-serif;max-width:1000px;margin:2em auto}"
             "table{border-collapse:collapse;width:100%}"
             "td,th{border:1px solid #ccc;padding:6px;text-align:left}"
             "th{background:#f0f0f0}.warn{color:#a00}</style></head><body>",
             "<h1>%s</h1><p>Generated %s</p>" % (_esc(case_name), now)]

    carved = findings.get("carved", [])
    parts.append("<h2>Carved files (%d)</h2>" % len(carved))
    if carved:
        parts.append("<table><tr><th>File</th><th>Type</th><th>Offset</th><th>Size</th></tr>")
        for c in carved:
            parts.append("<tr><td>%s</td><td>%s</td><td>%d</td><td>%d</td></tr>"
                         % (_esc(c["file"]), _esc(c["type"]), c["offset"], c["size"]))
        parts.append("</table>")
    else:
        parts.append("<p>None.</p>")

    msgs = findings.get("messages", [])
    parts.append("<h2>Messages extracted (%d)</h2>" % len(msgs))
    if msgs:
        parts.append("<table><tr><th>Chat</th><th>From me</th><th>Timestamp</th><th>Text</th></tr>")
        for m in msgs[:500]:
            parts.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
                         % (_esc(m.get("chat")), _esc(m.get("from_me")),
                            _esc(m.get("timestamp")), _esc((m.get("text") or "")[:200])))
        parts.append("</table>")
    else:
        parts.append("<p>None.</p>")

    frags = findings.get("deleted_fragments", [])
    parts.append("<h2>Possible deleted fragments (%d) <span class='warn'>— heuristic, review each</span></h2>" % len(frags))
    if frags:
        parts.append("<table><tr><th>Page</th><th>Offset</th><th>Fragment</th></tr>")
        for f in frags[:500]:
            parts.append("<tr><td>%d</td><td>%d</td><td>%s</td></tr>"
                         % (f["page"], f["offset"], _esc(f["text"][:200])))
        parts.append("</table>")
    else:
        parts.append("<p>None.</p>")

    notes = findings.get("notes", [])
    if notes:
        parts.append("<h2>Notes</h2><ul>")
        parts += ["<li>%s</li>" % _esc(n) for n in notes]
        parts.append("</ul>")

    parts.append("<p><em>Produced by WAForensic for authorized examination only.</em></p></body></html>")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(parts))

    # machine-readable copy alongside
    with open(os.path.splitext(out_path)[0] + ".json", "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2, default=str)
    return out_path
