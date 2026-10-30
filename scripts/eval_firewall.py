"""Firewall eval: Layer 1 alone vs Layer 1 + Layer 2 (Nemotron), on datasets/firewall_eval.json.

Texts: regex scanner alone vs regex + model scanner.  Calls: rules.py alone vs rules + policy judge.
Writes docs/firewall_eval.json and prints a table. Needs a model key (uses config.toml provider).
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "datasets"))

from gen_firewall_data import build

from redline.config import load_config
from redline.firewall.gate import Gate
from redline.firewall.policy import NanoPolicy
from redline.firewall.scanner import regex_scan, scan
from redline.llm import LLM
from redline.models import ToolCall


def prf(rows):  # rows: (label, predicted_positive)
    tp = sum(1 for lab, p in rows if lab and p)
    fp = sum(1 for lab, p in rows if not lab and p)
    fn = sum(1 for lab, p in rows if lab and not p)
    tn = sum(1 for lab, p in rows if not lab and not p)
    prec = tp / (tp + fp) if tp + fp else 1.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": round(prec, 3),
        "recall": round(rec, 3),
        "n": len(rows),
    }


def main():
    cfg = load_config()
    llm = LLM(cfg)
    data = build()
    ws = Path(tempfile.mkdtemp())
    (ws / "src").mkdir()
    (ws / "test").mkdir()
    (ws / "src" / "Vault.sol").write_text("contract Vault {}")

    t_l1, t_l12, misses = [], [], []
    for s in data["text"]:
        r = bool(regex_scan(s["text"]))
        _, q = scan("sample.txt", s["text"], llm, cfg.models.firewall)
        m = bool(q)
        t_l1.append((s["label"], r))
        t_l12.append((s["label"], r or m))
        if s["label"] != (r or m):
            misses.append({"kind": "text", "label": s["label"], "text": s["text"][:100]})

    c_l1, c_l12 = [], []
    g1 = Gate(ws)
    g2 = Gate(ws, policy=NanoPolicy(llm, cfg.models.firewall))
    for s in data["calls"]:
        call = ToolCall(**s["call"])
        d1 = g1.check(call).verdict == "deny"
        d2 = g2.check(call).verdict == "deny"
        c_l1.append((s["label"], d1))
        c_l12.append((s["label"], d2))
        if s["label"] != d2:
            misses.append({"kind": "call", "label": s["label"], "call": s["call"]})

    res = {
        "provider": cfg.active_provider,
        "firewall_model": cfg.models.firewall,
        "input_scanner": {"layer1_regex": prf(t_l1), "layer1_plus_model": prf(t_l12)},
        "action_gate": {"layer1_rules": prf(c_l1), "layer1_plus_policy_model": prf(c_l12)},
        "remaining_errors": misses,
    }
    out = ROOT / "docs" / "firewall_eval.json"
    out.write_text(json.dumps(res, indent=1))
    for sect in ("input_scanner", "action_gate"):
        print(sect)
        for k, v in res[sect].items():
            print(
                f"  {k:26s} P={v['precision']:.2f} R={v['recall']:.2f} "
                f"(tp={v['tp']} fp={v['fp']} fn={v['fn']} tn={v['tn']})"
            )
    print(f"remaining errors: {len(misses)} -> {out}")


if __name__ == "__main__":
    main()
