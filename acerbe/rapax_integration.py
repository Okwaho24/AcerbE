"""
AcerbE™ v3.1.0 — RaPaX™ Integration Module
Archer Chain Analytics™ | Mahihkan.com

Programmatic API for embedding AcerbE fingerprints into digital assets
at point of sale, inside RaPaX™ or any storefront/delivery pipeline.

No GUI. No server required. Direct function calls.

Usage inside RaPaX:

    from acerbe.rapax_integration import RaPaXFingerprinter

    fp = RaPaXFingerprinter()   # reads ACERBE_SECRET_KEY from env

    # At point of sale — bind the asset to the buyer:
    result = fp.fingerprint_for_sale(
        file_path="products/master/course.pdf",
        buyer_id="order_1a2b3c",           # order ID, email, or license ID
        output_dir="deliveries/order_1a2b3c",
    )
    # result.delivery_file  -> the file to hand the buyer
    # result.manifest_file  -> retain for enforcement
    # result.fingerprint    -> short ID for the receipt
    # result.output_hash    -> integrity anchor
"""

import os
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

from .engine import embed_fingerprint, verify_fingerprint


class AcerbeKeyError(RuntimeError):
    """Raised when ACERBE_SECRET_KEY is not configured."""


@dataclass
class SaleFingerprint:
    delivery_file: str
    manifest_file: str
    fingerprint:   str
    manifest_id:   str
    asset_hash:    str
    output_hash:   str
    timestamp:     str
    layers_active: int
    file_type:     str
    buyer_id:      str


class RaPaXFingerprinter:
    """
    Point-of-sale fingerprinting bridge between RaPaX™ and AcerbE™.
    Every asset sold is uniquely bound to the buyer before delivery.
    """

    def __init__(self, secret_key: Optional[str] = None):
        self._key = secret_key or os.environ.get("ACERBE_SECRET_KEY", "")
        if not self._key:
            raise AcerbeKeyError(
                "ACERBE_SECRET_KEY not set. Configure it before selling."
            )

    # ── Point of sale ─────────────────────────────────────────────────────────

    def fingerprint_for_sale(
        self,
        file_path: str | Path,
        buyer_id: str,
        output_dir: str | Path,
        product_name: Optional[str] = None,
    ) -> SaleFingerprint:
        """
        Fingerprint a master asset for a specific buyer at point of sale.

        The buyer_id becomes the owner_id in the fingerprint, so any leaked
        copy is traceable to the exact order that produced it.
        """
        file_path  = Path(file_path)
        output_dir = Path(output_dir)

        note = f"RaPaX sale | buyer={buyer_id}"
        if product_name:
            note += f" | product={product_name}"

        out_path, manifest_path, manifest = embed_fingerprint(
            file_path=file_path,
            owner_id=buyer_id,        # buyer-bound fingerprint
            secret_key=self._key,
            output_dir=output_dir,
            notes=note,
        )

        return SaleFingerprint(
            delivery_file=str(out_path),
            manifest_file=str(manifest_path),
            fingerprint=manifest.short_fingerprint,
            manifest_id=manifest.manifest_id,
            asset_hash=manifest.asset_hash,
            output_hash=manifest.output_hash,
            timestamp=manifest.iso_timestamp,
            layers_active=manifest.layer_status.layers_active(),
            file_type=manifest.file_type.value,
            buyer_id=buyer_id,
        )

    # ── Enforcement ───────────────────────────────────────────────────────────

    def trace_leak(self, suspect_file: str | Path) -> dict:
        """
        Given a suspected leaked file, extract and verify its fingerprint.
        Returns the buyer_id (owner) it was bound to, if verifiable.
        """
        report = verify_fingerprint(Path(suspect_file), self._key)
        return {
            "traceable":   report.get("verified", False),
            "bound_to":    report.get("owner"),
            "fingerprint": report.get("short_fingerprint"),
            "timestamp":   report.get("timestamp"),
            "full_report": report,
        }

    def verify_integrity(self, delivery_file: str | Path, expected_output_hash: str) -> bool:
        """
        Confirm a delivered file has not been altered since AcerbE processed it.
        Compares against the output_hash stored in the sale manifest.
        """
        import hashlib
        data = Path(delivery_file).read_bytes()
        return hashlib.sha256(data).hexdigest() == expected_output_hash


# ─── Demonstration ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import tempfile, secrets

    os.environ.setdefault("ACERBE_SECRET_KEY", "DEMO-KEY-FOR-LOCAL-TEST-ONLY-32CHARS")
    fp = RaPaXFingerprinter()

    tmp = Path(tempfile.mkdtemp())
    master = tmp / "course.pdf"
    master.write_bytes(b"%PDF-1.4\n%demo\n" + secrets.token_bytes(65536))

    sale = fp.fingerprint_for_sale(
        file_path=master,
        buyer_id="order_DEMO123",
        output_dir=tmp / "delivery",
        product_name="Sovereign Systems Course",
    )
    print("SALE FINGERPRINT")
    print("  delivery :", sale.delivery_file)
    print("  fp       :", sale.fingerprint)
    print("  bound to :", sale.buyer_id)
    print("  layers   :", sale.layers_active, "/4")
    print("  out hash :", sale.output_hash[:32], "...")

    trace = fp.trace_leak(sale.delivery_file)
    print("\nLEAK TRACE")
    print("  traceable:", trace["traceable"])
    print("  bound to :", trace["bound_to"])

    ok = fp.verify_integrity(sale.delivery_file, sale.output_hash)
    print("\nINTEGRITY CHECK:", "INTACT" if ok else "TAMPERED")
