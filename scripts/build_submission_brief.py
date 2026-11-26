"""Render the two-page brief from its Markdown source and recorded evidence."""

from __future__ import annotations

import json
import re
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib.colors import HexColor
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import Paragraph

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "docs/project_brief.md"
PDF = SOURCE.with_suffix(".pdf")


def brief_source():
    _, settings, body = SOURCE.read_text(encoding="utf-8").split("---", 2)
    name, video = settings.strip().split(":", 1)
    if name != "VIDEO_URL" or not video.strip():
        raise ValueError("Set VIDEO_URL at the top of docs/project_brief.md")
    return video.strip(), body


def evidence_values():
    evidence = json.loads((ROOT / "reports/judge-evidence.json").read_text(encoding="utf-8"))
    http = evidence["detector_http"]
    values = {
        "REVOCATION_MS": f"{evidence['timestamped_device_key_revocation']['last_denial_ms']:.3f}",
        "HTTP_MEDIAN": f"{http['median_ms']:.4f}",
        "HTTP_SAMPLES": str(len(http["samples_ms"])),
    }
    for group, name in (("REG", "regression"), ("CHALLENGE", "challenge")):
        for policy, mode in (("ALL", "all_severities"), ("HIGH", "non_low")):
            row = evidence["synthetic_detector_scores"][name][mode]
            values[f"{group}_{policy}_F1"] = f"{row['f1_score']:.4f}"
            values[f"{group}_{policy}_MEDIAN"] = f"{row['median_time_to_alert_ms']:.4f}"
            values[f"{group}_{policy}_FP"] = f"{row['false_alerts_per_1k']:g}"
    return values


def render_page(canvas, source, number, video):
    width, height = A4
    margin = 52
    text_width = width - 2 * margin
    navy = HexColor("#122C43")
    teal = HexColor("#08736F")
    y = height - 55
    canvas.setFillColor(teal)
    canvas.rect(margin, height - 36, 38, 4, fill=1, stroke=0)
    for raw in source.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("# "):
            text, font, size, leading, space, indent = line[2:], "Helvetica-Bold", 30, 35, 7, 0
        elif line.startswith("## "):
            y -= 10
            text, font, size, leading, space, indent = line[3:], "Helvetica-Bold", 15, 20, 4, 0
        else:
            indent = 12 if line.startswith("- ") else 0
            text = line[2:] if indent else line
            font, size, leading, space = "Helvetica", 10.5, 15, 6
        text = escape(text)
        if video.startswith(("https://", "http://")) or (SOURCE.parent / video).is_file():
            text = text.replace(escape(video), f'<link href="{escape(video, {chr(34): "&quot;"})}" color="#08736F">{escape(video)}</link>')
        style = ParagraphStyle("brief", fontName=font, fontSize=size, leading=leading,
                               textColor=navy, alignment=TA_LEFT)
        paragraph = Paragraph(text, style, bulletText="•" if indent else None)
        _, used = paragraph.wrap(text_width - indent, y)
        if y - used < 68:
            raise ValueError(f"Page {number} content would overlap the footer")
        paragraph.drawOn(canvas, margin + indent, y - used)
        y -= used + space
    canvas.setStrokeColor(HexColor("#B8CBD3"))
    canvas.line(margin, 52, width - margin, 52)
    canvas.setFont("Helvetica", 9)
    canvas.setFillColor(navy)
    canvas.drawString(margin, 36, "TRUST, BUT VERIFY  /  TRACK 4")
    canvas.drawRightString(width - margin, 36, f"{number} / 2")
    canvas.showPage()


def main():
    video, body = brief_source()
    values = {**evidence_values(), "VIDEO_URL": video}
    pages = re.sub(r"\{\{([A-Z0-9_]+)\}\}", lambda match: values[match[1]], body).split("\n---\n")
    if len(pages) != 2:
        raise ValueError("The source must contain exactly two pages")
    canvas = Canvas(str(PDF), pagesize=A4, invariant=1)
    canvas.setTitle("Trust, but verify | Track 4 project brief")
    for number, page in enumerate(pages, start=1):
        render_page(canvas, page, number, video)
    canvas.save()
    readme = ROOT / "README.md"
    text = readme.read_text(encoding="utf-8")
    if video.startswith(("http://", "https://")):
        label = f"<{video}>"
    elif (SOURCE.parent / video).is_file():
        label = f"[Walkthrough video](docs/{video})"
    else:
        label = f"`{video}`"
    updated, count = re.subn(r"^5-minute demo video:.*$", lambda _: f"5-minute demo video: {label}", text, flags=re.M)
    if count != 1:
        raise ValueError("README should have one 5-minute demo video line")
    readme.write_text(updated, encoding="utf-8")


if __name__ == "__main__":
    main()
