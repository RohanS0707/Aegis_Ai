# app.py - Aegis AI FastAPI Server

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import asyncio
import json
import threading
from datetime import datetime

from packet_engine import (
    process_connection, get_stats, get_blocked_ips,
    get_recent_detections, unblock_ip, detection_stats,
    email_queue, email_lock, blocked_ips
)

app = FastAPI(title="Aegis AI API", version="2.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ─── WebSocket Manager ────────────────────────────────────────────────────────
class WSManager:
    def __init__(self):
        self.active = []

    async def connect(self, ws):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws):
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, data):
        msg = json.dumps(data)
        dead = []
        for ws in self.active:
            try:
                await ws.send_text(msg)
            except:
                dead.append(ws)
        for ws in dead:
            if ws in self.active:
                self.active.remove(ws)

ws_manager = WSManager()

# ─── Broadcast Loop ───────────────────────────────────────────────────────────
async def broadcast_loop():
    last_count = 0
    while True:
        await asyncio.sleep(0.8)
        try:
            stats = get_stats()
            recent = get_recent_detections(5)
            if stats["total"] != last_count:
                last_count = stats["total"]
                await ws_manager.broadcast({
                    "type": "update",
                    "stats": {
                        "total": stats["total"],
                        "blocked": stats["blocked"],
                        "flagged": stats.get("flagged", 0),
                        "allowed": stats["total"] - stats["blocked"],
                        "attack_types": dict(stats.get("attack_types", {})),
                    },
                    "recent": recent[:5],
                    "timestamp": datetime.now().isoformat(),
                })
        except:
            pass

@app.on_event("startup")
async def startup():
    asyncio.create_task(broadcast_loop())
    # Sniffer background mein start karo
    def start_bg_sniffer():
        try:
            from sniffer import start_sniffer
            start_sniffer()
        except Exception as e:
            print(f"Sniffer: {e}")
    threading.Thread(target=start_bg_sniffer, daemon=True).start()
    print("✅ Aegis AI Server started on http://localhost:8000")

# ─── WebSocket ────────────────────────────────────────────────────────────────
@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws_manager.connect(ws)
    try:
        await ws.send_text(json.dumps({
            "type": "init",
            "stats": get_stats(),
            "detections": get_recent_detections(20),
            "blocked_ips": get_blocked_ips(),
        }))
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(ws)

# ─── REST APIs ────────────────────────────────────────────────────────────────
@app.get("/api/stats")
def api_stats():
    s = get_stats()
    return {
        "total": s["total"],
        "blocked": s["blocked"],
        "flagged": s.get("flagged", 0),
        "allowed": s["total"] - s["blocked"],
        "attack_types": dict(s.get("attack_types", {})),
        "ml_model": "XGBoost (UNSW-NB15)",
        "features": 42,
    }

@app.get("/api/detections")
def api_detections(limit: int = 50):
    return {"detections": get_recent_detections(limit)}

@app.get("/api/blocked-ips")
def api_blocked():
    return {"blocked_ips": get_blocked_ips()}

@app.delete("/api/blocked-ips/{ip}")
def api_unblock(ip: str):
    unblock_ip(ip)
    return {"message": f"{ip} unblocked"}

class SimRequest(BaseModel):
    attack_type: str = "DDoS"
    src_ip: str = "192.168.1.100"
    dst_ip: str = "192.168.1.1"
    sport: int = 12345
    dport: int = 80
    proto: str = "tcp"

@app.post("/api/simulate")
def api_simulate(req: SimRequest):
    """
    Attack simulate karo — attack_type pass karo
    process_connection attack_type se samjhega yeh real attack hai
    """
    profiles = {
        "DDoS":         dict(sbytes=500000, dbytes=100,  spkts=10000, dpkts=10),
        "Port Scan":    dict(sbytes=60000,  dbytes=0,    spkts=1000,  dpkts=0),
        "SQL Injection":dict(sbytes=2000,   dbytes=5000, spkts=10,    dpkts=8),
        "XSS":          dict(sbytes=1500,   dbytes=3000, spkts=8,     dpkts=6),
        "Brute Force":  dict(sbytes=50000,  dbytes=1000, spkts=1000,  dpkts=100),
        "CSRF":         dict(sbytes=1000,   dbytes=500,  spkts=5,     dpkts=3),
    }
    p = profiles.get(req.attack_type, dict(sbytes=5000, dbytes=100, spkts=500, dpkts=5))

    # ── KEY FIX: attack_type pass karo ──
    result = process_connection(
        src_ip=req.src_ip,
        dst_ip=req.dst_ip,
        sport=req.sport,
        dport=req.dport,
        proto=req.proto,
        attack_type=req.attack_type,   # ← YAHI FIX HAI
        **p
    )

    return result

@app.get("/api/alerts")
def api_alerts():
    from packet_engine import db_conn
    c = db_conn.cursor()
    c.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 20")
    cols = ["id", "timestamp", "message", "severity", "email_sent"]
    return {"alerts": [dict(zip(cols, r)) for r in c.fetchall()]}

@app.get("/api/model-info")
def api_model():
    from packet_engine import model
    return {
        "loaded": model is not None,
        "algorithm": "XGBoost Classifier",
        "dataset": "UNSW-NB15",
        "features": 42,
        "accuracy": "92%",
        "classes": ["Normal (0)", "Attack (1)"],
        "feature_names": list(model.feature_names_in_) if model else [],
    }

@app.get("/")
def root():
    return {"status": "online", "service": "Aegis AI", "version": "2.0.0"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=False)