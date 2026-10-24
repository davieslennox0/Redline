"""Input scanner: untrusted text -> (sanitized text, quarantined spans).

Two detectors, union of results: deterministic regexes (always on) and a small Nemotron model
(when an LLM is supplied). Flagged spans are replaced by a placeholder before any content reaches
the main agent. If a flagged line sits in a comment block, the whole block is quarantined.
"""
from __future__ import annotations

import re

from redline.models import Quarantine, ScanOut

PATTERNS: list[tuple[str, re.Pattern]] = [(n, re.compile(p, re.I)) for n, p in [
    ("override-instructions", r"(ignore|disregard|forget|override)\b.{0,40}\b(previous|prior|above|"
                              r"all|your)\b.{0,30}\b(instructions?|prompts?|rules?)"),
    ("addresses-ai", r"\b(note|message|instructions?|attention)\b.{0,20}\b(to|for)\b.{0,15}"
                     r"\b(ai|llm|automated|language model)\b|\b(ai|llm) (security )?(auditors?|"
                     r"reviewers?|agents?|assistants?)\b|\bautomated audit agents?\b"),
    ("suppress-findings", r"(report|say|state|write)\b.{0,25}\b(no|zero|0)\b.{0,15}"
                          r"\b(issues?|vulnerabilit|findings?|bugs?)|do not report|don'?t report|"
                          r"(already|previously)\b.{0,25}\b(audited|verified)\b.{0,60}\b(safe|no )"),
    ("run-command", r"(curl|wget)\b[^\n]{0,120}\|\s*(sudo\s+)?(sh|bash|zsh)\b|"
                    r"\b(execute|run)\b.{0,30}(curl|wget|bash|\bsh\b|setup script)"),
    ("exfiltrate-env", r"\b(print|echo|dump|show|include|output|leak|send)\b.{0,40}"
                       r"\b(env(ironment)?( variables?)?|api[ _-]?keys?|secrets?|credentials?|"
                       r"\.env|private keys?)\b|\bcat\b[^\n]{0,15}~?/?\.env\b"),
]]

_LINE_COMMENT = re.compile(r"^\s*(///?|\*|/\*|\*/|#|<!--|-->)")


def _comment_regions(lines: list[str]) -> list[tuple[int, int]]:
    """0-based inclusive (start, end) line ranges that are comments (// runs, /* */, <!-- -->)."""
    regions: list[tuple[int, int]] = []
    i = 0
    while i < len(lines):
        s = lines[i].strip()
        if s.startswith(("<!--", "/*")):
            closer = "-->" if s.startswith("<!--") else "*/"
            j = i
            while j < len(lines) and closer not in lines[j]:
                j += 1
            regions.append((i, min(j, len(lines) - 1)))
            i = j + 1
        elif s.startswith("//"):
            j = i
            while j + 1 < len(lines) and lines[j + 1].strip().startswith("//"):
                j += 1
            # split a /// run into NatSpec tag blocks so benign @title/@notice survive
            starts = [k for k in range(i, j + 1)
                      if k == i or re.match(r"^\s*///?\s*@\w+", lines[k])]
            for n, a in enumerate(starts):
                regions.append((a, (starts[n + 1] - 1) if n + 1 < len(starts) else j))
            i = j + 1
        else:
            i += 1
    return regions


def regex_scan(text: str) -> dict[int, str]:
    """Return {0-based line: detector name} for lines matching an injection pattern."""
    hits: dict[int, str] = {}
    for n, line in enumerate(text.splitlines()):
        for name, pat in PATTERNS:
            if pat.search(line):
                hits[n] = name
                break
    # patterns split over wrapped comment lines: also test the comment region joined
    lines = text.splitlines()
    for a, b in _comment_regions(lines):
        if any(a <= h <= b for h in hits):
            continue
        joined = " ".join(re.sub(r"^\s*(///?|\*+|<!--|-->)\s?", "", ln) for ln in lines[a:b + 1])
        for name, pat in PATTERNS:
            if pat.search(joined):
                hits[a] = name
                break
    return hits


def scan(file: str, text: str, llm=None, model: str = "") -> tuple[str, list[Quarantine]]:
    lines = text.splitlines()
    flagged: dict[int, tuple[str, str]] = {n: ("regex", d) for n, d in regex_scan(text).items()}
    if llm is not None and lines:
        try:
            numbered = "\n".join(f"{i + 1}: {ln[:300]}" for i, ln in enumerate(lines[:800]))
            from redline.agent.prompts import SCANNER_SYSTEM

            out = llm.structured(model, [
                {"role": "system", "content": SCANNER_SYSTEM},
                {"role": "user", "content": f"<untrusted_data file={file!r}>\n{numbered}\n"
                                            "</untrusted_data>"}], ScanOut, role="scanner",
                max_tokens=512)
            for ln in out.injected_lines:
                if 1 <= ln <= len(lines):
                    flagged.setdefault(ln - 1, ("model", out.reason[:120] or "model-flagged"))
        except Exception as e:  # scanner model down: regex layer still protects
            flagged.setdefault(-1, ("model-error", str(e)[:120]))
    flagged.pop(-1, None)
    if not flagged:
        return text, []

    regions = _comment_regions(lines)
    spans: list[tuple[int, int, str, str]] = []
    for n, (det, why) in sorted(flagged.items()):
        a, b = next(((s, e) for s, e in regions if s <= n <= e), (n, n))
        spans.append((a, b, det, why))
    spans.sort()
    merged: list[list] = []
    for a, b, det, why in spans:
        if merged and a <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], b)
        else:
            merged.append([a, b, det, why])

    out_lines = list(lines)
    qs: list[Quarantine] = []
    for k, (a, b, det, why) in enumerate(reversed(merged)):
        idx = len(merged) - k
        excerpt = " ".join(x.strip() for x in lines[a:b + 1])[:300]
        qs.append(Quarantine(file=file, start_line=a + 1, end_line=b + 1, detector=det,
                             reason=why, excerpt=excerpt))
        out_lines[a:b + 1] = [f"[REDACTED #{idx}: suspected prompt injection removed by "
                              f"Redline firewall ({file}:{a + 1}-{b + 1})]"]
    qs.reverse()
    return "\n".join(out_lines) + ("\n" if text.endswith("\n") else ""), qs
