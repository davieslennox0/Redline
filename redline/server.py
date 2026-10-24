"""`redline serve`: FastAPI app. Serves the UI, run list/detail, and an SSE event stream."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from redline.config import ROOT
from redline.events import read_events

WEB = Path(__file__).parent / "web"
RUN_DIRS = [ROOT / "jobs", ROOT / "samples"]


def find_run(run_id: str) -> Path | None:
    if "/" in run_id or ".." in run_id:
        return None
    for base in RUN_DIRS:
        d = base / run_id
        if (d / "events.jsonl").exists():
            return d
    return None


def summarize(d: Path) -> dict:
    evs = read_events(d / "events.jsonl")
    start = next((e for e in evs if e["type"] == "run_started"), {})
    end = next((e for e in reversed(evs) if e["type"] == "run_finished"), None)
    return {"id": d.name, "repo": start.get("repo", d.name), "provider": start.get("provider", ""),
            "scripted": start.get("scripted", False), "label": start.get("label", ""),
            "started": start.get("ts", 0), "status": "running" if not end else
            ("finished" if end["ok"] else "failed"),
            "findings": sum(e["type"] == "finding_added" for e in evs),
            "confirmed": sum(e["type"] == "poc_result" and e["confirmed"] for e in evs)}


def load_run(d: Path) -> dict:
    rp = d / "report.json"
    return {"id": d.name, "report": json.loads(rp.read_text()) if rp.exists() else None,
            "events": read_events(d / "events.jsonl")}


def create_app() -> FastAPI:
    app = FastAPI(title="Redline run viewer")

    @app.get("/runs")
    def runs():
        out = [summarize(p.parent) for base in RUN_DIRS if base.exists()
               for p in base.glob("*/events.jsonl")]
        return sorted(out, key=lambda r: r["started"], reverse=True)

    @app.get("/runs/{run_id}")
    def run(run_id: str):
        d = find_run(run_id)
        if not d:
            raise HTTPException(404, "no such run")
        return load_run(d)

    @app.get("/runs/{run_id}/stream")
    async def stream(run_id: str, speed: float = 1.0, replay: bool = True):
        """SSE. Finished runs are replayed with their recorded timing (clamped); live runs tail."""
        d = find_run(run_id)
        if not d:
            raise HTTPException(404, "no such run")
        path = d / "events.jsonl"

        async def gen():
            sent, prev_ts, idle = 0, None, 0.0
            finished_at_start = any(e["type"] == "run_finished" for e in read_events(path))
            while True:
                evs = read_events(path)
                for e in evs[sent:]:
                    if finished_at_start and replay and prev_ts is not None:
                        await asyncio.sleep(min(max(e["ts"] - prev_ts, 0.15), 2.5) / max(speed, .1))
                    prev_ts = e["ts"]
                    yield f"id: {e['seq']}\nevent: {e['type']}\ndata: {json.dumps(e)}\n\n"
                    sent += 1
                    idle = 0.0
                    if e["type"] == "run_finished":
                        yield "event: end\ndata: {}\n\n"
                        return
                await asyncio.sleep(0.25)
                idle += 0.25
                if idle > 600:
                    return
                if int(idle * 4) % 60 == 59:
                    yield ": keepalive\n\n"

        return StreamingResponse(gen(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    @app.get("/")
    def index():
        return FileResponse(WEB / "index.html")

    app.mount("/static", StaticFiles(directory=WEB), name="static")
    return app
