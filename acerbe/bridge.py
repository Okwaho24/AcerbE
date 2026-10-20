"""
AcerbE(TM) v3.1.0 - RaPaX(TM) bridge.

POST /fingerprint
  Header: X-AcerbE-Key: <ACERBE_API_KEY>
  Body:   { product_id, transaction_id, buyer_wallet?, timestamp?, file_path }
  Reads   products/... object from object storage (R2/S3),
  embeds a per-transaction fingerprint, writes fingerprinted/<transaction_id>/...,
  returns { fingerprinted_file_path, fingerprint_id, hash }.

Environment (all required; the service fails closed if any is missing):
  ACERBE_API_KEY, ACERBE_SECRET_KEY,
  R2_ENDPOINT, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, R2_BUCKET_NAME
"""
import hashlib
import hmac
import os
import re
import tempfile
from pathlib import Path
from typing import Optional

import boto3
from botocore.config import Config
from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field

from .engine import embed_fingerprint

router = APIRouter()

MAX_BYTES = int(os.environ.get("ACERBE_MAX_FILE_MB", "200")) * 1024 * 1024
_SAFE_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_REQUIRED = ("ACERBE_API_KEY", "ACERBE_SECRET_KEY", "R2_ENDPOINT",
             "R2_ACCESS_KEY_ID", "R2_SECRET_ACCESS_KEY", "R2_BUCKET_NAME")


class FingerprintRequest(BaseModel):
    product_id: str = Field(min_length=1, max_length=128)
    transaction_id: str = Field(min_length=1, max_length=128)
    buyer_wallet: Optional[str] = Field(default=None, max_length=256)
    timestamp: Optional[str] = None
    file_path: str = Field(min_length=1, max_length=512)


def _client():
    return boto3.client(
        "s3",
        endpoint_url=os.environ["R2_ENDPOINT"],
        aws_access_key_id=os.environ["R2_ACCESS_KEY_ID"],
        aws_secret_access_key=os.environ["R2_SECRET_ACCESS_KEY"],
        region_name="auto",
        config=Config(
            signature_version="s3v4",
            s3={"addressing_style": "path"},
            # R2 and other S3-compatible stores reject the newer default checksum framing.
            request_checksum_calculation="when_required",
            response_checksum_validation="when_required",
            connect_timeout=10,
            read_timeout=60,
            retries={"max_attempts": 3, "mode": "standard"},
        ),
    )


_REQUIRED_DOC = ("ACERBE_API_KEY", "ACERBE_SECRET_KEY")


def _check_key(provided: Optional[str], required=_REQUIRED) -> None:
    missing = [k for k in required if not os.environ.get(k)]
    if missing:
        raise HTTPException(503, detail="Service not configured: " + ", ".join(missing))
    # Fail closed on weak or unresolved secrets (e.g. a literal "${{secret(48)}}" template that never expanded).
    weak = [k for k in ("ACERBE_API_KEY", "ACERBE_SECRET_KEY")
            if k in required and (len(os.environ[k]) < 32 or "${" in os.environ[k])]
    if weak:
        raise HTTPException(503, detail="Service not configured securely: " + ", ".join(weak))
    if not provided or not hmac.compare_digest(provided, os.environ["ACERBE_API_KEY"]):
        raise HTTPException(401, detail="Invalid API key.")


@router.post("/fingerprint")
def fingerprint(req: FingerprintRequest, x_acerbe_key: Optional[str] = Header(default=None)):
    _check_key(x_acerbe_key)

    key = req.file_path
    if not key.startswith("products/") or ".." in key or key.startswith("/"):
        raise HTTPException(400, detail="file_path must be a products/ object key.")
    if not _SAFE_ID.match(req.transaction_id):
        raise HTTPException(400, detail="Invalid transaction_id.")

    bucket = os.environ["R2_BUCKET_NAME"]
    s3 = _client()
    name = Path(key).name

    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "in" / name
        out_dir = Path(tmp) / "out"
        src.parent.mkdir()
        out_dir.mkdir()

        try:
            head = s3.head_object(Bucket=bucket, Key=key)
        except Exception as e:
            raise HTTPException(404, detail=f"Product file not found: {type(e).__name__}")
        if head["ContentLength"] > MAX_BYTES:
            raise HTTPException(413, detail="Product file too large.")
        body = s3.get_object(Bucket=bucket, Key=key)["Body"]
        written = 0
        with open(src, "wb") as fh:
            for chunk in iter(lambda: body.read(1024 * 1024), b""):
                written += len(chunk)
                if written > MAX_BYTES:
                    raise HTTPException(413, detail="Product file too large.")
                fh.write(chunk)

        owner = f"{req.transaction_id}|{req.buyer_wallet or 'anonymous'}"
        try:
            out_path, _manifest_path, manifest = embed_fingerprint(
                file_path=src,
                owner_id=owner,
                secret_key=os.environ["ACERBE_SECRET_KEY"],
                output_dir=out_dir,
                notes=f"product={req.product_id}",
            )
        except Exception as e:
            raise HTTPException(500, detail=f"Fingerprinting failed: {e}")

        data = out_path.read_bytes()
        out_key = f"fingerprinted/{req.transaction_id}/{name}"
        s3.put_object(Bucket=bucket, Key=out_key, Body=data,
                      ContentType=head.get("ContentType", "application/octet-stream"))

    return {
        "fingerprinted_file_path": out_key,
        "fingerprint_id": manifest.manifest_id,
        "hash": hashlib.sha256(data).hexdigest(),
    }


# ─── LexForge(TM) document registration ───────────────────────────────────────

_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")


class DocFingerprintRequest(BaseModel):
    transactionId: str = Field(min_length=1, max_length=128)
    documentCode: str = Field(min_length=1, max_length=32)
    contentHash: str
    filename: str = Field(min_length=1, max_length=256)


@router.post("/api/v1/fingerprint")
def register_document(req: DocFingerprintRequest, x_acerbe_key: Optional[str] = Header(default=None)):
    """
    RECORD-ONLY registration for text documents delivered by LexForge(TM).
    The document itself is NOT modified: the returned fingerprint_id is an HMAC-SHA256 binding of
    (transaction, document code, content hash, filename) under ACERBE_SECRET_KEY, so it can be
    re-derived and checked later, but it is not embedded in the file.
    """
    _check_key(x_acerbe_key, _REQUIRED_DOC)
    if not _SAFE_ID.match(req.transactionId) or not _HASH.match(req.contentHash):
        raise HTTPException(400, detail="Invalid transactionId or contentHash.")
    msg = "|".join([req.transactionId, req.documentCode, req.contentHash, req.filename]).encode("utf-8")
    digest = hmac.new(os.environ["ACERBE_SECRET_KEY"].encode("utf-8"), msg, hashlib.sha256).hexdigest()
    return {"fingerprint_id": "ACERBE-DOC-" + digest[:20].upper(), "mode": "record-only"}
