"""FastAPI server for Zero-Trust Network Map.

Provides:
- REST API for triggering scans and querying results
- WebSocket for real-time scan progress updates
- Static file serving for the React frontend
"""
from __future__ import annotations

import asyncio
import json
import os
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import uvicorn

from models import ScanResult
from scanner import scan_network
from trust_analyzer import ZeroTrustAnalyzer

app = FastAPI(title="Zero-Trust Network Map", version="1.0.0")

# CORS for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for scan results
scan_results: dict[str, ScanResult] = {}
scan_history: list[str] = []

# WebSocket connections
ws_connections: list[WebSocket] = []

# Thread pool for background scans
executor = ThreadPoolExecutor(max_workers=2)

# Path to frontend static files
FRONTEND_DIR = Path(__file__).parent.parent / "frontend" / "dist"


async def broadcast_progress(status: str, percent: int, message: str, scan_id: str = ""):
    """Broadcast scan progress to all connected WebSocket clients."""
    data = json.dumps({
        "type": "scan_progress",
        "scan_id": scan_id,
        "status": status,
        "percent": percent,
        "message": message,
    })
    for ws in ws_connections.copy():
        try:
            await ws.send_text(data)
        except Exception:
            if ws in ws_connections:
                ws_connections.remove(ws)


async def broadcast_scan_result(scan_id: str, result: dict):
    """Broadcast a complete scan result to all WebSocket clients."""
    data = json.dumps({
        "type": "scan_complete",
        "scan_id": scan_id,
        "result": result,
    })
    for ws in ws_connections.copy():
        try:
            await ws.send_text(data)
        except Exception:
            if ws in ws_connections:
                ws_connections.remove(ws)


def run_scan_in_background(network: str, scan_id: str, loop: asyncio.AbstractEventLoop):
    """Run a network scan in a background thread and broadcast results."""
    def progress_callback(status, percent, message):
        asyncio.run_coroutine_threadsafe(
            broadcast_progress(status, percent, message, scan_id),
            loop,
        )

    try:
        result = scan_network(network=network, progress_callback=progress_callback)

        # Run zero-trust analysis
        analyzer = ZeroTrustAnalyzer(result)
        analysis = analyzer.analyze()

        # Store result (cap history to prevent unbounded growth)
        scan_results[scan_id] = result
        scan_history.append(scan_id)
        if len(scan_history) > 100:
            old_id = scan_history.pop(0)
            scan_results.pop(old_id, None)

        # Broadcast complete result with analysis
        result_dict = result.to_dict()
        result_dict["zero_trust_analysis"] = analysis

        asyncio.run_coroutine_threadsafe(
            broadcast_scan_result(scan_id, result_dict),
            loop,
        )
    except Exception as e:
        asyncio.run_coroutine_threadsafe(
            broadcast_progress("failed", 0, f"Scan failed: {str(e)}", scan_id),
            loop,
        )


@app.get("/api/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok", "timestamp": time.time()}


@app.post("/api/scan")
async def start_scan(network: Optional[str] = None):
    """Start a new network scan."""
    scan_id = str(uuid.uuid4())[:8]
    loop = asyncio.get_event_loop()

    # Start scan in background thread
    threading.Thread(
        target=run_scan_in_background,
        args=(network, scan_id, loop),
        daemon=True,
    ).start()

    return {
        "scan_id": scan_id,
        "status": "started",
        "message": "Scan started successfully",
    }


@app.get("/api/scan/{scan_id}")
async def get_scan_result(scan_id: str):
    """Get the result of a completed scan."""
    if scan_id in scan_results:
        result = scan_results[scan_id].to_dict()
        analyzer = ZeroTrustAnalyzer(scan_results[scan_id])
        result["zero_trust_analysis"] = analyzer.analyze()
        return result
    return {"error": "Scan not found", "scan_id": scan_id}


@app.get("/api/scans")
async def list_scans():
    """List all completed scans."""
    scan_list = []
    for sid in scan_history[-20:]:  # Last 20 scans
        if sid in scan_results:
            r = scan_results[sid]
            scan_list.append({
                "scan_id": sid,
                "network": r.network,
                "timestamp": r.timestamp,
                "total_devices": r.total_devices,
                "overall_risk_score": r.overall_risk_score,
                "scan_duration_seconds": r.scan_duration_seconds,
                "scan_status": r.scan_status,
            })
    return {"scans": scan_list}


@app.get("/api/network-info")
async def get_network_info():
    """Get information about the current network."""
    from scanner import get_local_network
    network = get_local_network()
    return {"network": network}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time scan updates."""
    await websocket.accept()
    ws_connections.append(websocket)
    try:
        while True:
            # Keep connection alive and listen for commands
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("action") == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        if websocket in ws_connections:
            ws_connections.remove(websocket)
    except Exception:
        if websocket in ws_connections:
            ws_connections.remove(websocket)


# Serve frontend static files
if FRONTEND_DIR.exists():
    app.mount("/assets", StaticFiles(directory=str(FRONTEND_DIR / "assets")), name="assets")

    @app.get("/{full_path:path}")
    async def serve_frontend(full_path: str):
        """Serve the React frontend for all non-API routes."""
        if full_path.startswith("api/"):
            from fastapi.responses import JSONResponse
            return JSONResponse({"error": "Not found"}, status_code=404)
        index_path = FRONTEND_DIR / "index.html"
        if index_path.exists():
            return FileResponse(str(index_path))
        return {"error": "Frontend not built. Run: cd frontend && npm run build"}


if __name__ == "__main__":
    print("Starting Zero-Trust Network Map server...")
    print("API: http://localhost:8000")
    print("Frontend: http://localhost:8000 (after building)")
    uvicorn.run(app, host="0.0.0.0", port=8000)
