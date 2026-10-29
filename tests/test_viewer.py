import json
import re

import pytest
from fastapi.testclient import TestClient

from redline.config import ROOT
from redline.events import parse_event, read_events
from redline.export import build_html
from redline.server import create_app, load_run

SAMPLES = ["sample-vulnerable-vault", "sample-poisoned-repo"]


@pytest.fixture(scope="module")
def client():
    return TestClient(create_app())


@pytest.mark.parametrize("name", SAMPLES)
def test_sample_events_valid_and_flagged_scripted(name):
    evs = [
        parse_event(json.dumps(e)) for e in read_events(ROOT / "samples" / name / "events.jsonl")
    ]
    assert evs[0].type == "run_started" and evs[0].scripted and "SAMPLE" in evs[0].label
    assert evs[-1].type == "run_finished" and evs[-1].ok
    assert all(c.prompt_tokens == 0 for c in evs if c.type == "llm_call")  # no fake token numbers


def test_runs_api_and_detail(client):
    runs = client.get("/runs").json()
    assert {r["id"] for r in runs} >= set(SAMPLES)
    d = client.get("/runs/sample-poisoned-repo").json()
    assert d["report"]["quarantine_files"] and d["events"]
    assert client.get("/runs/nope").status_code == 404
    assert client.get("/runs/..%2Fetc").status_code in (404, 422)


def test_sse_replays_all_events_then_ends(client):
    n = len(read_events(ROOT / "samples/sample-vulnerable-vault/events.jsonl"))
    with client.stream("GET", "/runs/sample-vulnerable-vault/stream?speed=100") as r:
        body = "".join(r.iter_text())
    assert body.count("\nevent: ") + body.startswith("event: ") >= n
    assert "event: run_finished" in body and "event: end" in body


def test_export_is_self_contained(tmp_path):
    html = build_html(load_run(ROOT / "samples/sample-poisoned-repo"))
    assert "__REDLINE_DATA__" in html and "SAMPLE" in html
    assert not re.search(r'(src|href)="https?://', html.split("window.__REDLINE_DATA__")[0])
    assert "<script src=" not in html and "<link " not in html
    assert not re.search(r"^import .* from ", html, flags=re.M)  # ES module imports were stripped
    assert not re.search(r"^export ", html, flags=re.M)
