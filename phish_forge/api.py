"""Optional FastAPI service. Install extras: pip install 'phish-forge[api]'."""

from __future__ import annotations

from fastapi import FastAPI, File, HTTPException, UploadFile

from .scoring import analyze

app = FastAPI(
    title="phish-forge",
    description="Drop a .eml in, get a phishing verdict out.",
    version="0.1.0",
)

@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}

@app.post("/analyze")
async def analyze_endpoint(file: UploadFile = File(...)) -> dict:
    if not file:
        raise HTTPException(status_code=400, detail="missing file")
    raw = (await file.read()).decode("utf-8", errors="replace")
    if not raw.strip():
        raise HTTPException(status_code=400, detail="empty file")
    report = analyze(raw)
    return report.to_dict()
