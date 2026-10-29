"""Patch: propose a minimal fix; PoC must stop working AND the existing suite must stay green."""

from __future__ import annotations

import difflib

from redline.agent.prompts import PATCH_SYSTEM
from redline.agent.recon import render_repo
from redline.agent.tools import Tools
from redline.firewall.gate import GateDenied
from redline.models import Finding, PatchDraft, PatchResult, PoCResult


def _diff(path: str, old: str, new: str) -> str:
    return "".join(
        difflib.unified_diff(old.splitlines(True), new.splitlines(True), f"a/{path}", f"b/{path}")
    )


def run_patch(
    llm, cfg, tools: Tools, finding: Finding, poc: PoCResult, files: dict[str, str]
) -> PatchResult:
    originals = {k: tools.read(k) for k in files if k.startswith("src/")}  # real, unredacted src
    feedback = ""
    res = PatchResult(applied=False, attempts=0)
    for attempt in range(1, cfg.limits.max_patch_attempts + 1):
        res.attempts = attempt
        user = (
            f"Finding: {finding.model_dump_json()}\n\nExploit test:\n{poc.code}\n\n"
            f"Source files:\n{render_repo({k: v for k, v in files.items() if k.startswith('src/')})}"
            f"{feedback}"
        )
        draft = llm.structured(
            cfg.models.main,
            [{"role": "system", "content": PATCH_SYSTEM}, {"role": "user", "content": user}],
            PatchDraft,
            role="patch",
            max_tokens=14000,
            thinking=True,
        )
        try:
            for e in draft.edits:
                tools.write(e.path, e.content, purpose=f"patch for {finding.id}")
        except GateDenied as e:
            res.note = f"blocked by firewall: {e}"
            feedback = f"\n\nYour patch was blocked by the security gate: {e}"
            _restore(tools, originals)
            continue
        poc_run = tools.forge(
            f"test --match-path {poc.test_file}", purpose="re-run PoC after patch"
        )
        suite = tools.forge(f"test --no-match-path {poc.test_file}", purpose="existing tests")
        blocked = (
            poc_run.ok and bool(poc_run.results) and not all(r.passed for r in poc_run.results)
        )
        res.poc_blocked, res.suite_green = blocked, suite.all_passed
        res.output = (suite.stderr or suite.stdout)[-800:]
        if blocked and suite.all_passed:
            res.applied = True
            res.diff = "\n".join(
                _diff(e.path, originals.get(e.path, ""), e.content) for e in draft.edits
            )
            res.note = draft.rationale
            _restore(tools, originals)  # keep findings independent; the diff is recorded
            return res
        res.note = "exploit still works" if not blocked else "existing tests broke"
        feedback = (
            f"\n\nAttempt {attempt} failed: {res.note}. Suite output:\n{res.output}\n"
            f"PoC forge output:\n{(poc_run.stderr or poc_run.stdout)[-800:]}"
        )
        _restore(tools, originals)
    return res


def _restore(tools: Tools, originals: dict[str, str]) -> None:
    for p, c in originals.items():
        tools.write(p, c, purpose="restore original after failed patch")
