import threading
from contextlib import asynccontextmanager

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from . import engine
from .config import MODEL, ROOT, has_api_key, scope_allowlist, suricata_eve_path
from .models import Alert
from .sensors import suricata
from .sensors.demo import random_alert
from .store import store


@asynccontextmanager
async def lifespan(app):
    if suricata_eve_path():
        threading.Thread(target=suricata.watch, daemon=True).start()
    yield


app = FastAPI(title="SentinelAgent", lifespan=lifespan)
WEB = ROOT / "web"
app.mount("/web", StaticFiles(directory=WEB), name="web")


@app.get("/")
def index():
    return FileResponse(WEB / "index.html")


@app.get("/api/status")
def status():
    return {"has_key": has_api_key(), "model": MODEL, "scope": scope_allowlist()}


@app.get("/api/alerts")
def list_alerts():
    return [r.model_dump() for r in store.all()]


@app.get("/api/alerts/{aid}")
def get_alert(aid: str):
    rec = store.get(aid)
    if not rec:
        raise HTTPException(404, "alert not found")
    return rec.model_dump()


@app.post("/api/alerts")
def ingest(alert: Alert):
    return store.add_alert(alert).model_dump()


@app.post("/api/demo")
def demo():
    return store.add_alert(random_alert()).model_dump()


@app.post("/api/alerts/{aid}/triage")
def triage(aid: str, bg: BackgroundTasks):
    rec = store.get(aid)
    if not rec:
        raise HTTPException(404, "alert not found")
    rec.status = "triaging"
    bg.add_task(engine.triage, rec)
    return {"ok": True}


@app.post("/api/alerts/{aid}/apply")
def apply(aid: str, bg: BackgroundTasks):
    rec = store.get(aid)
    if not rec:
        raise HTTPException(404, "alert not found")
    if not rec.verdict:
        raise HTTPException(400, "no verdict yet")
    rec.status = "remediating"
    bg.add_task(engine.remediate, rec)
    return {"ok": True}
