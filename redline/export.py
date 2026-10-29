"""Build a single self-contained HTML file from the same web assets the server uses."""

from __future__ import annotations

import json
import re
from pathlib import Path

WEB = Path(__file__).parent / "web"
ORDER = ["highlight.js", "state.js", "views.js", "main.js"]


def _strip_modules(src: str) -> str:
    src = re.sub(r"^import\s[^;]*?from\s+['\"][^'\"]+['\"];?\s*$", "", src, flags=re.M)
    return re.sub(r"^export\s+", "", src, flags=re.M)


def build_html(data: dict) -> str:
    css = (WEB / "app.css").read_text()
    js = "\n".join(_strip_modules((WEB / "js" / f).read_text()) for f in ORDER)
    # `</` inside JSON must not terminate the script element
    payload = json.dumps(data).replace("</", "<\\/").replace("<!--", "<\\!--")
    title = f"Redline - {data['id']}"
    return (
        f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
        f'<meta name="viewport" content="width=device-width, initial-scale=1">'
        f'<title>{title}</title><style>{css}</style></head><body><div id="app"></div>'
        f"<script>window.__REDLINE_DATA__ = {payload};</script>"
        f"<script>(function(){{\n{js}\n}})();</script></body></html>"
    )
