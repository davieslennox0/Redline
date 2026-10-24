"""Generate SAMPLE runs with the scripted (mock) LLM. Real forge/scanner/firewall, fake model text.

Run:  uv run python scripts/gen_samples.py
Output: samples/<run_id>/{events.jsonl,report.json,firewall.jsonl}  (workspace copy removed)
"""
import shutil

from redline.agent import orchestrator
from redline.config import ROOT, load_config
from redline.scripted import ScriptedLLM

LABEL = "SAMPLE - scripted model"


def main() -> None:
    cfg = load_config()
    cfg.active_provider = cfg.active_provider  # provider recorded as configured; calls are mock
    for name in ("vulnerable-vault", "poisoned-repo"):
        res = orchestrator.audit(ROOT / "fixtures" / name, cfg, ScriptedLLM(name), log=print,
                                 do_research=False, run_name=f"sample-{name}", scripted=True,
                                 label=LABEL, out_root=ROOT / "samples")
        shutil.rmtree(ROOT / "samples" / res.run_id / "ws", ignore_errors=True)


if __name__ == "__main__":
    main()
