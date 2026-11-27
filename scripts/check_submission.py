"""Validate the submission PDF and every link in the root README."""

from __future__ import annotations

import argparse
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlsplit
from urllib.request import Request, urlopen

from pypdf import PdfReader

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN = ("TODO", "trust-but-verify.dev/demo-walkthrough", "/Users/", "file://")
LINK_PATTERNS = (
    r"\]\(<?([^\s<>)]+)>?(?:\s+\"[^\"]*\")?\)",
    r"<(https?://[^>\s]+)>",
    r"(?mi)^\s*\[[^\]]+\]:\s*<?([^\s<>]+)>?",
    r"""(?i)\b(?:href|src)=["']([^"']+)["']""",
)


def heading_ids(text):
    counts = {}
    for heading in re.findall(r"(?m)^#{1,6}\s+(.+?)\s*#*\s*$", text):
        slug = re.sub(r"[^\w\s-]", "", heading.lower()).replace(" ", "-")
        index = counts.get(slug, 0)
        counts[slug] = index + 1
        yield f"{slug}-{index}" if index else slug


def check_link(destination):
    url = urlsplit(destination)
    if url.scheme in {"http", "https"}:
        try:
            for method in ("HEAD", "GET"):
                try:
                    request = Request(destination, headers={"User-Agent": "Track4-Submission-Check/1.0"}, method=method)
                    with urlopen(request, timeout=12):
                        return None
                except HTTPError:
                    if method == "GET":
                        raise
        except (URLError, TimeoutError, OSError) as exc:
            return f"cannot verify {destination}: {exc}"
    elif url.scheme:
        return f"unsupported link: {destination}"
    else:
        part = unquote(url.path)
        path = ROOT / "README.md" if not part else ROOT / part.lstrip("/")
        if not path.exists():
            return f"missing README link target: {destination}"
        if url.fragment and path.suffix.lower() == ".md":
            text = path.read_text(encoding="utf-8")
            fragment = unquote(url.fragment)
            if fragment not in set(heading_ids(text)) and f'id="{fragment}"' not in text:
                return f"missing README link anchor: {destination}"
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--require-public-video", action="store_true",
        help="require the configured HTTPS walkthrough link in the PDF and README",
    )
    args = parser.parse_args()
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    pdf = PdfReader(ROOT / "docs/project_brief.pdf")
    errors = []
    if len(pdf.pages) != 2:
        errors.append(f"expected two PDF pages, found {len(pdf.pages)}")

    pdf_text = []
    pdf_links = set()
    for page in pdf.pages:
        pdf_text.append(page.extract_text() or "")
        for annotation in page.get("/Annots", []):
            action = annotation.get_object().get("/A", {})
            if action.get("/URI"):
                destination = str(action["/URI"])
                pdf_links.add(destination)
                pdf_text.append(destination)
    for name, contents in (("README.md", readme), ("docs/project_brief.pdf", "\n".join(pdf_text))):
        errors.extend(f"{name} contains forbidden text: {word}" for word in FORBIDDEN if word in contents)

    prose = re.sub(r"(?ms)^(`{3,}|~{3,})[^\n]*\n.*?^\1[ \t]*$", "", readme)
    links = sorted({link for pattern in LINK_PATTERNS for link in re.findall(pattern, prose)})
    if args.require_public_video:
        source = (ROOT / "docs/project_brief.md").read_text(encoding="utf-8")
        video = re.search(r"(?m)^VIDEO_URL:\s*(\S+)$", source)
        url = urlsplit(video[1]) if video else None
        if url is None or url.scheme != "https" or not url.hostname:
            errors.append("Set VIDEO_URL in docs/project_brief.md to the public HTTPS walkthrough URL.")
        elif video[1] not in pdf_links or video[1] not in links:
            errors.append("Rebuild the brief so the public walkthrough URL appears in both the PDF and README.")

    with ThreadPoolExecutor(max_workers=8) as pool:
        errors.extend(error for error in pool.map(check_link, links) if error is not None)
    if errors:
        raise SystemExit("\n".join(errors))
    print(f"Submission check passed: two PDF pages and {len(links)} README links.")


if __name__ == "__main__":
    main()
