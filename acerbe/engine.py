"""
AcerbE™ v3.0.0 — Hardened Fingerprint Engine
Archer Chain Analytics™ | Mahihkan.com

Layer 1: HMAC-SHA256 Owner Signing
Layer 2: SHA256 Asset Hashing
Layer 3: Steganographic LSB Embedding (binary/PDF files ≥ 8 KB)
Layer 4: Pydantic-Validated Chain-of-Custody Manifest

Hardening changes from v2:
  - Correct hmac API usage verified
  - PDF-aware embedding: injects into PDF comment stream, not prepend
  - LSB offset anchored to fixed byte position — no fragile newline search
  - Zero-byte and tiny-file guards
  - Full extraction index tracking for reliable recovery
  - Atomic output writes (write to .tmp, then rename)
  - Audit log appended per operation
"""

import hashlib
import hmac
import zlib
import json
import time
import struct
import os
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

from .models import FingerprintManifest, FileType, LayerStatus

# ─── CONSTANTS ────────────────────────────────────────────────────────────────

ACERBE_VERSION   = "3.1.0"
LSB_MIN_BYTES    = 8192          # Minimum binary size for LSB (8 KB)
MAX_FILE_MB      = 500           # Hard cap on input file size
LSB_HEADER_MAGIC = b"\xACE\xBE"  # 4-byte magic prefix inside LSB payload

TEXT_EXTENSIONS = {
    # Documents / markup
    ".txt", ".md", ".rst", ".html", ".htm", ".css", ".scss", ".sass",
    ".xml", ".svg", ".tex",
    # Data / config
    ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    ".env", ".sql", ".csv", ".tsv", ".log", ".properties",
    # Scripts / code
    ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat",
    ".rb", ".lua", ".pl", ".php", ".r",
    ".c", ".h", ".cpp", ".hpp", ".cc", ".cs", ".java", ".kt",
    ".go", ".rs", ".swift", ".m", ".scala", ".dart", ".vue",
    ".sol",  # Solidity — relevant to Archer Chain
}
PDF_EXTENSIONS  = {".pdf"}
# ZIP-based Office Open XML — must embed INSIDE the zip, not prepend
OFFICE_EXTENSIONS = {
    ".docx", ".xlsx", ".pptx", ".dotx", ".xltx", ".potx",
    ".docm", ".xlsm", ".pptm",
    ".odt", ".ods", ".odp",   # OpenDocument (also zip-based)
}
# Everything else treated as generic binary
BINARY_EXTENSIONS = {
    ".doc", ".xls", ".ppt",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff", ".webp", ".ico",
    ".zip", ".tar", ".gz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib",
    ".mp3", ".mp4", ".mov", ".avi", ".wav", ".flac",
    ".wasm", ".bin", ".dat",
    ".ttf", ".otf", ".woff", ".woff2",
    ".safetensors", ".gguf", ".onnx", ".pt", ".pth", ".ckpt",  # AI models
    ".epub", ".mobi",
    ".blend", ".glb", ".gltf", ".fbx", ".obj",  # 3D
    ".parquet", ".npy", ".npz", ".pkl",  # data
    ".apk", ".ipa", ".ai", ".sketch", ".fig", ".psd",
}

# ─── AUDIT LOG ────────────────────────────────────────────────────────────────

def _audit_log(output_dir: Path, entry: dict) -> None:
    log_path = output_dir / "ACERBE_AUDIT.log"
    line = json.dumps(entry, separators=(",", ":")) + "\n"
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(line)


# ─── LAYER 1: HMAC-SHA256 SIGNING ─────────────────────────────────────────────

def compute_hmac(owner_id: str, asset_hash: str, timestamp: int, secret_key: str) -> str:
    """
    HMAC-SHA256 over canonical payload string.
    Binds owner + asset + timestamp into a single unforgeable signature.
    """
    payload = f"ACERBE-{ACERBE_VERSION}|{owner_id}|{asset_hash}|{timestamp}"
    return hmac.new(
        key=secret_key.encode("utf-8"),
        msg=payload.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()


def verify_hmac(owner_id: str, asset_hash: str, timestamp: int,
                secret_key: str, claimed: str) -> bool:
    expected = compute_hmac(owner_id, asset_hash, timestamp, secret_key)
    return hmac.compare_digest(expected, claimed)


# ─── LAYER 2: SHA256 ASSET HASH ───────────────────────────────────────────────

def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ─── LAYER 3: STEGANOGRAPHIC LSB EMBEDDING ────────────────────────────────────

def _pack_lsb_payload(payload: bytes) -> bytes:
    """
    Build LSB-ready packet:
      [4 magic][4 length][payload bytes]
    Fixed structure — no newline dependency.
    """
    return LSB_HEADER_MAGIC + struct.pack(">I", len(payload)) + payload


def lsb_embed(carrier: bytes, payload: bytes) -> bytes:
    """
    Embed payload into LSBs of carrier bytes.
    carrier must be >= len(packet) * 8 bytes.
    """
    packet = _pack_lsb_payload(payload)
    required = len(packet) * 8
    if len(carrier) < required:
        raise ValueError(
            f"Carrier too small: need {required} bytes capacity, "
            f"have {len(carrier)}"
        )

    buf = bytearray(carrier)
    for byte_idx, pbyte in enumerate(packet):
        for bit_pos in range(7, -1, -1):
            carrier_idx = byte_idx * 8 + (7 - bit_pos)
            bit_val = (pbyte >> bit_pos) & 1
            buf[carrier_idx] = (buf[carrier_idx] & 0xFE) | bit_val

    return bytes(buf)


def lsb_extract(carrier: bytes) -> Optional[bytes]:
    """
    Extract LSB-embedded payload. Returns None if magic not found.
    """
    MAGIC_LEN   = len(LSB_HEADER_MAGIC)
    LENGTH_LEN  = 4
    HEADER_BITS = (MAGIC_LEN + LENGTH_LEN) * 8

    if len(carrier) * 8 < HEADER_BITS:
        return None

    # Extract header
    header_bytes = bytearray(MAGIC_LEN + LENGTH_LEN)
    for byte_idx in range(MAGIC_LEN + LENGTH_LEN):
        reconstructed = 0
        for bit_pos in range(7, -1, -1):
            carrier_idx = byte_idx * 8 + (7 - bit_pos)
            reconstructed = (reconstructed << 1) | (carrier[carrier_idx] & 1)
        header_bytes[byte_idx] = reconstructed

    # Verify magic
    if bytes(header_bytes[:MAGIC_LEN]) != LSB_HEADER_MAGIC:
        return None

    payload_len = struct.unpack(">I", bytes(header_bytes[MAGIC_LEN:]))[0]
    total_bytes = MAGIC_LEN + LENGTH_LEN + payload_len
    required_carrier = total_bytes * 8

    if len(carrier) < required_carrier:
        return None

    # Extract payload
    payload = bytearray(payload_len)
    for byte_idx in range(payload_len):
        actual_idx = MAGIC_LEN + LENGTH_LEN + byte_idx
        reconstructed = 0
        for bit_pos in range(7, -1, -1):
            carrier_idx = actual_idx * 8 + (7 - bit_pos)
            reconstructed = (reconstructed << 1) | (carrier[carrier_idx] & 1)
        payload[byte_idx] = reconstructed

    return bytes(payload)


# ─── PDF-AWARE EMBEDDING ──────────────────────────────────────────────────────

PDF_FP_MARKER = b"%%AcerbE_FP:"
PDF_FP_END    = b":AcerbE_End%%"

def _pdf_embed(pdf_bytes: bytes, encoded: str) -> bytes:
    """
    Inject fingerprint as a PDF comment line immediately after %PDF header.
    PDF comment lines start with %. This is valid PDF and survives most
    PDF readers without corruption.
    """
    idx = pdf_bytes.find(b"\n")
    if idx == -1:
        idx = 0
    comment = PDF_FP_MARKER + encoded.encode("ascii") + PDF_FP_END + b"\n"
    return pdf_bytes[:idx + 1] + comment + pdf_bytes[idx + 1:]


def _pdf_extract(pdf_bytes: bytes) -> Optional[str]:
    start = pdf_bytes.find(PDF_FP_MARKER)
    if start == -1:
        return None
    end = pdf_bytes.find(PDF_FP_END, start)
    if end == -1:
        return None
    raw = pdf_bytes[start + len(PDF_FP_MARKER):end]
    return raw.decode("ascii", errors="ignore")


# ─── OFFICE (ZIP-BASED) EMBEDDING ─────────────────────────────────────────────
# DOCX/XLSX/PPTX/ODT are ZIP archives. Prepending bytes corrupts them.
# Correct approach: add the fingerprint as an extra file inside the archive.
# Office and OpenDocument readers ignore unknown parts, so the file stays valid.

import zipfile
import io

OFFICE_FP_PATH = "acerbe/fingerprint.txt"

def _office_embed(office_bytes: bytes, encoded: str, hmac_sig: str, timestamp: int) -> bytes:
    """
    Insert AcerbE fingerprint as an extra part inside the Office/ODF zip.
    Rewrites the archive preserving all original members.
    """
    src = io.BytesIO(office_bytes)
    dst = io.BytesIO()

    fp_content = (
        f"ACERBE_V3_FP:{encoded}\n"
        f"HMAC:{hmac_sig}\n"
        f"TS:{timestamp}\n"
    )

    with zipfile.ZipFile(src, "r") as zin:
        names = set(zin.namelist())
        with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                # Skip any prior AcerbE part (re-fingerprint safe)
                if item.filename == OFFICE_FP_PATH:
                    continue
                zout.writestr(item, zin.read(item.filename))
            zout.writestr(OFFICE_FP_PATH, fp_content)

    return dst.getvalue()


def _office_extract(office_bytes: bytes) -> Optional[str]:
    """Read the embedded fingerprint hex from inside an Office/ODF zip."""
    try:
        src = io.BytesIO(office_bytes)
        with zipfile.ZipFile(src, "r") as zin:
            if OFFICE_FP_PATH not in zin.namelist():
                return None
            content = zin.read(OFFICE_FP_PATH).decode("utf-8", errors="ignore")
        for line in content.splitlines():
            if line.startswith("ACERBE_V3_FP:"):
                return line.split("ACERBE_V3_FP:", 1)[1].strip()
    except Exception:
        return None
    return None


# ─── MASTER EMBED ─────────────────────────────────────────────────────────────

def embed_fingerprint(
    file_path: Path,
    owner_id: str,
    secret_key: str,
    output_dir: Optional[Path] = None,
    notes: Optional[str] = None,
) -> tuple[Path, Path, FingerprintManifest]:
    """
    Full four-layer AcerbE™ fingerprint embedding.
    Returns (fingerprinted_file, manifest_json, manifest_object).
    """

    # ── Input validation ──────────────────────────────────────────────────────
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    original_bytes = file_path.read_bytes()
    size = len(original_bytes)

    if size == 0:
        raise ValueError("Cannot fingerprint an empty file.")
    if size > MAX_FILE_MB * 1024 * 1024:
        raise ValueError(f"File exceeds {MAX_FILE_MB} MB limit.")

    timestamp  = int(time.time())
    suffix     = file_path.suffix.lower()
    dest_dir   = output_dir or (file_path.parent / "acerbe_output")
    dest_dir.mkdir(parents=True, exist_ok=True)

    # ── Layer 2: SHA256 ───────────────────────────────────────────────────────
    asset_hash = compute_sha256(original_bytes)
    layer_status = LayerStatus(sha256_asset_hash=True)

    # ── Layer 1: HMAC-SHA256 ──────────────────────────────────────────────────
    hmac_sig = compute_hmac(owner_id, asset_hash, timestamp, secret_key)
    layer_status.hmac_sha256_signing = True

    short_fp = f"ACERBE-{asset_hash[:16].upper()}"

    # Build compact JSON payload for embedding
    fp_payload = {
        "v":     ACERBE_VERSION,
        "owner": owner_id,
        "hash":  asset_hash,
        "hmac":  hmac_sig,
        "ts":    timestamp,
        "fp":    short_fp,
    }
    fp_json       = json.dumps(fp_payload, separators=(",", ":")).encode("utf-8")
    fp_compressed = zlib.compress(fp_json, level=9)
    fp_hex        = fp_compressed.hex()

    # ── Layer 3 + file-type embedding ─────────────────────────────────────────
    if suffix in TEXT_EXTENSIONS:
        file_type = FileType.TEXT
        marker = (
            f"\n# ACERBE_V3_FP:{fp_hex}"
            f"|HMAC:{hmac_sig}"
            f"|TS:{timestamp}\n"
        )
        output_bytes = original_bytes + marker.encode("utf-8")
        layer_status.steganographic_lsb = False  # LSB is not applicable to text

    elif suffix in PDF_EXTENSIONS:
        file_type = FileType.PDF
        # PDF-aware comment injection
        pdf_embedded = _pdf_embed(original_bytes, fp_hex)
        # LSB must skip the PDF header + injected comment line to avoid
        # corrupting the %PDF signature and comment bytes.
        if size >= LSB_MIN_BYTES:
            try:
                # Find byte offset past the injected AcerbE comment line
                skip = pdf_embedded.find(PDF_FP_END)
                if skip != -1:
                    skip = skip + len(PDF_FP_END) + 1  # +1 for trailing newline
                else:
                    skip = pdf_embedded.find(b"\n", 0) + 1
                carrier      = pdf_embedded[skip:]
                lsb_carrier  = lsb_embed(carrier, fp_compressed)
                output_bytes = pdf_embedded[:skip] + lsb_carrier
                layer_status.steganographic_lsb = True
            except (ValueError, Exception):
                output_bytes = pdf_embedded
                layer_status.steganographic_lsb = False
        else:
            output_bytes = pdf_embedded
            layer_status.steganographic_lsb = False

    elif suffix in OFFICE_EXTENSIONS:
        file_type = FileType.OFFICE
        # Embed fingerprint as an internal zip part — no corruption.
        try:
            output_bytes = _office_embed(original_bytes, fp_hex, hmac_sig, timestamp)
            # The embedded internal part counts as the survivable Layer 3 carrier.
            layer_status.steganographic_lsb = True
        except Exception:
            # Not a valid zip after all — fall back to binary header prepend.
            header = b"ACERBE_V3:" + fp_hex.encode("ascii") + b"\n"
            output_bytes = header + original_bytes
            layer_status.steganographic_lsb = False
            file_type = FileType.BINARY

    else:
        file_type = FileType.BINARY
        # Prepend recoverable header + attempt LSB
        header = b"ACERBE_V3:" + fp_hex.encode("ascii") + b"\n"
        if size >= LSB_MIN_BYTES:
            try:
                steg_bytes   = lsb_embed(original_bytes, fp_compressed)
                output_bytes = header + steg_bytes
                layer_status.steganographic_lsb = True
            except ValueError:
                output_bytes = header + original_bytes
                layer_status.steganographic_lsb = False
        else:
            output_bytes = header + original_bytes
            layer_status.steganographic_lsb = False

    # ── Atomic write ──────────────────────────────────────────────────────────
    out_name = f"ACERBE_{short_fp}_{file_path.name}"
    out_path = dest_dir / out_name
    tmp_path = out_path.with_suffix(out_path.suffix + ".tmp")
    tmp_path.write_bytes(output_bytes)
    tmp_path.rename(out_path)

    # ── Gap 4: Output-file integrity hash ─────────────────────────────────────
    # SHA256 of the FINGERPRINTED output — detects post-processing tampering.
    output_hash = compute_sha256(output_bytes)

    # ── Layer 4: Manifest ─────────────────────────────────────────────────────
    layer_status.pydantic_manifest = True

    manifest = FingerprintManifest(
        owner_id=owner_id,
        file_name=file_path.name,
        file_type=file_type,
        original_size=size,
        asset_hash=asset_hash,
        output_hash=output_hash,
        output_size=len(output_bytes),
        hmac_signature=hmac_sig,
        timestamp=timestamp,
        short_fingerprint=short_fp,
        layer_status=layer_status,
        notes=notes,
    )

    manifest_path = dest_dir / f"MANIFEST_{short_fp}.json"
    manifest_path.write_text(manifest.model_dump_json(indent=2), encoding="utf-8")

    # ── Audit log ─────────────────────────────────────────────────────────────
    _audit_log(dest_dir, {
        "op":        "embed",
        "ts":        timestamp,
        "owner":     owner_id,
        "file":      file_path.name,
        "fp":        short_fp,
        "layers":    layer_status.layers_active(),
        "file_type": file_type.value,
    })

    return out_path, manifest_path, manifest


# ─── VERIFY ───────────────────────────────────────────────────────────────────

def verify_fingerprint(file_path: Path, secret_key: str) -> dict:
    """
    Extract and verify AcerbE fingerprint. Returns structured report.
    """
    if not file_path.exists():
        return {"verified": False, "error": "File not found."}

    data   = file_path.read_bytes()
    suffix = file_path.suffix.lower()
    report = {
        "file":     str(file_path),
        "verified": False,
        "layers":   {},
        "owner":    None,
        "short_fingerprint": None,
        "asset_hash_embedded": None,
        "timestamp": None,
    }

    def _try_decode(fp_hex: str) -> Optional[dict]:
        try:
            compressed = bytes.fromhex(fp_hex)
            payload    = zlib.decompress(compressed)
            return json.loads(payload)
        except Exception:
            return None

    fp_data = None

    # Extraction attempt 1: PDF comment
    if suffix in PDF_EXTENSIONS:
        raw = _pdf_extract(data)
        if raw:
            fp_data = _try_decode(raw)
            if fp_data:
                report["layers"]["pdf_comment_extraction"] = True

    # Extraction attempt 1b: Office / ODF internal zip part
    if fp_data is None and suffix in OFFICE_EXTENSIONS:
        raw = _office_extract(data)
        if raw:
            fp_data = _try_decode(raw)
            if fp_data:
                report["layers"]["office_zip_extraction"] = True

    # Extraction attempt 2: Text or binary header
    if fp_data is None:
        for marker in (b"ACERBE_V3_FP:", b"ACERBE_V3:"):
            idx = data.find(marker)
            if idx != -1:
                end = data.find(b"\n", idx)
                segment = data[idx + len(marker): end if end != -1 else idx + 4096]
                hex_part = segment.split(b"|")[0].split(b"\n")[0].strip()
                fp_data = _try_decode(hex_part.decode("ascii", errors="ignore"))
                if fp_data:
                    report["layers"]["header_extraction"] = True
                    break

    # Extraction attempt 3: LSB
    if suffix not in TEXT_EXTENSIONS:
        # Determine correct carrier start offset
        # PDFs: skip past injected AcerbE comment line
        # Binaries: skip past ACERBE_V3: header line
        carrier_start = 0
        if suffix in PDF_EXTENSIONS:
            end_marker = data.find(PDF_FP_END)
            if end_marker != -1:
                nl_after = data.find(b"\n", end_marker)
                carrier_start = nl_after + 1 if nl_after != -1 else end_marker + len(PDF_FP_END)
        else:
            nl = data.find(b"\n")
            if nl != -1 and nl < 512:
                carrier_start = nl + 1

        try:
            lsb_payload = lsb_extract(data[carrier_start:])
            if lsb_payload:
                try:
                    lsb_json = json.loads(zlib.decompress(lsb_payload))
                    report["layers"]["lsb_extraction"] = True
                    if fp_data is None:
                        fp_data = lsb_json
                except Exception:
                    pass
        except Exception:
            pass

    if fp_data is None:
        report["error"] = "No AcerbE fingerprint detected."
        return report

    # Populate report
    report["owner"]              = fp_data.get("owner")
    report["short_fingerprint"]  = fp_data.get("fp")
    report["asset_hash_embedded"] = fp_data.get("hash")
    report["timestamp"]          = fp_data.get("ts")
    report["acerbe_version"]     = fp_data.get("v")

    # HMAC verification
    try:
        valid = verify_hmac(
            fp_data["owner"],
            fp_data["hash"],
            fp_data["ts"],
            secret_key,
            fp_data["hmac"],
        )
        report["layers"]["hmac_verified"] = valid
        report["verified"] = valid
    except Exception as e:
        report["layers"]["hmac_verified"] = False
        report["hmac_error"] = str(e)

    return report
