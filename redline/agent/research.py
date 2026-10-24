"""Research: Tavily lookups for real-world precedents. Results are untrusted and scanned."""
from __future__ import annotations

import os

from redline.agent.tools import Tools
from redline.firewall import scanner
from redline.models import Citation, Finding, Quarantine

TAVILY_URL = "https://api.tavily.com/search"


def research(tools: Tools, finding: Finding, llm=None, scan_model: str = "",
             quarantined: list[Quarantine] | None = None) -> list[Citation]:
    key = os.environ.get("TAVILY_API_KEY")
    if not key:
        return []
    q = f"smart contract {finding.title} exploit post-mortem real world hack"
    data = tools.post_json(TAVILY_URL, {"query": q, "max_results": 4, "search_depth": "basic"},
                           {"Authorization": f"Bearer {key}"}, purpose="find public exploit write-ups")
    cites: list[Citation] = []
    for r in data.get("results", []):
        clean, qs = scanner.scan(r.get("url", "web"), r.get("content", "")[:1500], llm, scan_model)
        if quarantined is not None:
            quarantined += qs
        cites.append(Citation(title=r.get("title", "")[:150], url=r.get("url", ""), snippet=clean[:400]))
    return cites
