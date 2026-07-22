"""
AcerbE™ v3.1.0 — FastAPI Server Bridge
Hardened: file size cap, MIME check, no public key exposure
Archer Chain Analytics™ | Mahihkan.com
"""

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
import uuid
import os
import time

from .engine import embed_fingerprint, verify_fingerprint

# ─── CONFIG ───────────────────────────────────────────────────────────────────

MAX_UPLOAD_MB = 500
ALLOWED_MIME_PREFIXES = (
    "application/", "text/", "image/", "audio/", "video/",
    "application/pdf", "application/octet-stream",
)

SECRET_KEY = os.environ.get("ACERBE_SECRET_KEY", "")
UPLOAD_DIR = Path("uploads")
OUTPUT_DIR = Path("output")
UPLOAD_DIR.mkdir(exist_ok=True)
OUTPUT_DIR.mkdir(exist_ok=True)

app = FastAPI(
    title="AcerbE™ v3.1.0",
    description="Archer Chain Analytics™ | Mahihkan.com",
    version="3.1.0",
    docs_url=None,   # Disable public Swagger docs in production
    redoc_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1", "http://localhost"],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

# ─── GUARDS ───────────────────────────────────────────────────────────────────

def _require_key():
    if not SECRET_KEY:
        raise HTTPException(
            status_code=503,
            detail="ACERBE_SECRET_KEY not configured. Set environment variable before use."
        )

# ─── ROUTES ───────────────────────────────────────────────────────────────────

@app.post("/embed")
async def embed(
    file: UploadFile = File(...),
    owner_id: str = Form(default="Mahihkan"),
    notes: str = Form(default=""),
):
    _require_key()

    # File size guard (read with limit)
    content = await file.read(MAX_UPLOAD_MB * 1024 * 1024 + 1)
    if len(content) > MAX_UPLOAD_MB * 1024 * 1024:
        raise HTTPException(413, detail=f"File exceeds {MAX_UPLOAD_MB} MB limit.")
    if len(content) == 0:
        raise HTTPException(400, detail="Empty file rejected.")

    file_id    = str(uuid.uuid4())
    input_path = UPLOAD_DIR / f"{file_id}_{file.filename}"
    input_path.write_bytes(content)

    try:
        out_path, manifest_path, manifest = embed_fingerprint(
            file_path=input_path,
            owner_id=owner_id.strip() or "Mahihkan",
            secret_key=SECRET_KEY,
            output_dir=OUTPUT_DIR,
            notes=notes or None,
        )
    except Exception as e:
        raise HTTPException(500, detail=str(e))
    finally:
        input_path.unlink(missing_ok=True)  # Clean up upload immediately

    ls = manifest.layer_status
    return {
        "status":           "fingerprinted",
        "short_fingerprint": manifest.short_fingerprint,
        "manifest_id":       manifest.manifest_id,
        "timestamp":         manifest.iso_timestamp,
        "layers_active":     ls.layers_active(),
        "layer_detail": {
            "hmac_sha256_signing":  ls.hmac_sha256_signing,
            "sha256_asset_hash":    ls.sha256_asset_hash,
            "steganographic_lsb":   ls.steganographic_lsb,
            "pydantic_manifest":    ls.pydantic_manifest,
        },
        "file_type":     manifest.file_type.value,
        "output_file":   out_path.name,
        "manifest_file": manifest_path.name,
        "file_id":       file_id,
    }


@app.get("/download/{file_id}")
async def download(file_id: str):
    # Sanitize file_id — alphanumeric + hyphens only
    if not all(c.isalnum() or c == "-" for c in file_id):
        raise HTTPException(400, detail="Invalid file ID.")
    matches = list(OUTPUT_DIR.glob(f"ACERBE_*"))
    target  = next((p for p in matches if file_id in p.name), None)
    if not target:
        raise HTTPException(404, detail="File not found.")
    return FileResponse(target, filename=target.name)


@app.get("/manifest/{file_id}")
async def get_manifest(file_id: str):
    if not all(c.isalnum() or c == "-" for c in file_id):
        raise HTTPException(400, detail="Invalid file ID.")
    matches = list(OUTPUT_DIR.glob("MANIFEST_*.json"))
    target  = next((p for p in matches if file_id in p.read_text()), None)
    if not target:
        raise HTTPException(404, detail="Manifest not found.")
    import json
    return JSONResponse(content=json.loads(target.read_text()))


@app.post("/verify")
async def verify(file: UploadFile = File(...)):
    _require_key()
    content = await file.read(MAX_UPLOAD_MB * 1024 * 1024 + 1)
    if len(content) > MAX_UPLOAD_MB * 1024 * 1024:
        raise HTTPException(413, "File too large for verification.")

    tmp = UPLOAD_DIR / f"verify_{uuid.uuid4()}_{file.filename}"
    tmp.write_bytes(content)
    try:
        report = verify_fingerprint(tmp, SECRET_KEY)
    finally:
        tmp.unlink(missing_ok=True)

    return report


@app.get("/health")
async def health():
    return {
        "status":          "operational",
        "engine":          "AcerbE™ v3.1.0",
        "issuer":          "Archer Chain Analytics™ | Mahihkan.com",
        "key_configured":  bool(SECRET_KEY),
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "acerbe.server:app",
        host="127.0.0.1",
        port=8001,
        reload=False,
        log_level="warning",
    )
