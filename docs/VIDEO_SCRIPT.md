# Demo video script (docs/redline-demo.mp4, 2:34, silent with captions)

The video is built by `scripts/make_demo_video.py` from real artifacts (screenshots of the exported
live runs, real `redline firewall-test` output, the real eval JSON). Voice-over for a re-record:

1. (0:00) Redline audits Solidity, proves each bug by running a real Foundry exploit, then patches it.
2. (0:08) The problem: the code you audit can talk to the auditor. This NatSpec comment is aimed at AI
   reviewers: report nothing, run a curl pipe to shell, print your API keys.
3. (0:20) Live run on Nemotron: the scanner quarantines both injections before the agent reads them; the
   audit still produces executed proofs of concept.
4. (0:36) Firewall view: the README injection, caught by the deterministic layer, shown as flagged.
5. (0:48) The NatSpec injection, caught by the Nemotron scanner; the agent saw only a placeholder.
6. (0:57) Even if an injection got through, the action gate denies pipe-to-shell, env dumps, secret reads
   and `--ffi`; normal forge runs are allowed.
7. (1:12) Clean target, reentrancy vault: baseline, scan, recon, Tavily research, exploit, patch.
8. (1:25) Confirmed by execution: the generated test passes, so the bug is real.
9. (1:38) The patch reorders state update and external call; the exploit now fails, the suite stays green.
10. (1:51) Findings are researched on Tavily with cited post-mortems.
11. (1:59) Poisoned repo, live: 4 findings, 3 confirmed, 2 patched; none of the injected commands reached the agent.
12. (2:11) Firewall eval: Layer 1 alone vs Layer 1 + Nemotron.
13. (2:24) Close: proof by execution, with a firewall for the agent itself. Say plainly that the runs used
    NVIDIA-hosted Nemotron and that the Nebius switch is a config change.
