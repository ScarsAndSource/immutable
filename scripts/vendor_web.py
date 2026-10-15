#!/usr/bin/env python3
"""scripts/vendor_web.py: make the web console work with no internet.

Run once on a connected machine:   python scripts/vendor_web.py
Check only (no network):           python scripts/vendor_web.py --check

Downloads Tailwind (pinned), Google Fonts (latin, latin-ext, devanagari) and a subset of
Material Symbols into web/vendor/, rewrites web/index.html to use them (a backup goes to
index.html.bak), and writes web/vendor/MANIFEST.txt with SHA-256 of every file so the
copy you carry to the lab is the copy you downloaded.
"""
import argparse
import hashlib
import html as htmllib
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WEB = ROOT / "web"
VENDOR = WEB / "vendor"
TAILWIND_URL = "https://cdn.tailwindcss.com/3.4.17"
DEVANAGARI = "https://fonts.googleapis.com/css2?family=Noto+Sans+Devanagari:wght@400;500;600&display=swap"
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/124.0 Safari/537.36")                      # a modern UA makes Google serve woff2
KEEP = {"latin", "latin-ext", "devanagari"}
EXTERNAL = re.compile(r"""(?:src|href)\s*=\s*["'](https?://[^"']+)["']|url\(\s*["']?(https?://[^)"']+)""", re.I)
ICON = re.compile(r"material-symbols-outlined[^>]*>\s*([a-z0-9_]+)\s*<")


def get(url: str, ua: str | None = None) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": ua or "immutable-vendor/1"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read()


def external_refs() -> list[tuple[str, str]]:
    out = []
    for name in ("index.html", "style.css", "app.js", "safe.js"):
        p = WEB / name
        if p.exists():
            for m in EXTERNAL.finditer(p.read_text(encoding="utf-8")):
                out.append((name, m.group(1) or m.group(2)))
    return out


def icon_names(extra: list[str]) -> list[str]:
    names = set(extra)
    for name in ("index.html", "app.js"):
        names |= set(ICON.findall((WEB / name).read_text(encoding="utf-8")))
    return sorted(names)


def localize(css: str) -> str:
    out = []
    for m in re.finditer(r"(?:/\*\s*([\w-]+)\s*\*/\s*)?(@font-face\s*\{.*?\})", css, re.S):
        subset, block = m.group(1), m.group(2)
        if subset is not None and subset not in KEEP:
            continue

        def sub(u):
            url = u.group(1).strip("'\" ")
            name = hashlib.sha256(url.encode()).hexdigest()[:12] + ".woff2"
            dest = VENDOR / "fonts" / name
            if not dest.exists():
                dest.write_bytes(get(url))
            return f"url(fonts/{name})"

        out.append(re.sub(r"url\(([^)]+)\)", sub, block))
    return "\n".join(out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--full-icons", action="store_true", help="whole icon font instead of a subset")
    ap.add_argument("--extra-icon", action="append", default=[], help="icon names set from JavaScript")
    a = ap.parse_args()

    if a.check:
        refs = external_refs()
        for f, u in refs:
            print(f"external: {f}: {u}")
        print("no external references" if not refs else f"{len(refs)} external reference(s)")
        return 1 if refs else 0

    index = WEB / "index.html"
    text = index.read_text(encoding="utf-8")
    css_urls = [htmllib.unescape(u) for u in
                re.findall(r'href="(https://fonts\.googleapis\.com/css2[^"]+)"', text)]
    (VENDOR / "fonts").mkdir(parents=True, exist_ok=True)

    (VENDOR / "tailwind.js").write_bytes(get(TAILWIND_URL))
    css_parts = []
    for url in css_urls:
        if "Material+Symbols" in url and not a.full_icons:
            url += "&icon_names=" + ",".join(icon_names(a.extra_icon))
        css_parts.append(localize(get(url, UA).decode("utf-8")))
    css_parts.append(localize(get(DEVANAGARI, UA).decode("utf-8")))
    (VENDOR / "fonts.css").write_text("\n".join(css_parts), encoding="utf-8")

    bak = WEB / "index.html.bak"
    if not bak.exists():
        bak.write_text(text, encoding="utf-8")
    text = re.sub(r"[ \t]*<link[^>]*fonts\.(?:googleapis|gstatic)\.com[^>]*>[ \t]*\n?", "", text)
    text = text.replace('<script src="https://cdn.tailwindcss.com"></script>',
                        '<script src="vendor/tailwind.js"></script>')
    if "vendor/fonts.css" not in text:
        text = text.replace("</head>", '  <link rel="stylesheet" href="vendor/fonts.css">\n</head>', 1)
    if "safe.js" not in text:
        text = text.replace('<script src="app.js"></script>',
                            '<script src="safe.js"></script>\n  <script src="app.js"></script>', 1)
    index.write_text(text, encoding="utf-8")

    lines = [f"tailwind.js  <- {TAILWIND_URL}"]
    for p in sorted(VENDOR.rglob("*")):
        if p.is_file() and p.name != "MANIFEST.txt":
            lines.append(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(VENDOR)}")
    (VENDOR / "MANIFEST.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    left = external_refs()
    for f, u in left:
        print(f"still external: {f}: {u}")
    print("done. Now disconnect from the internet and load the console to confirm.")
    return 1 if left else 0


if __name__ == "__main__":
    sys.exit(main())
