"""
AcerbE™ v3.0.0 — Manifest Schema
Layer 4: Pydantic-Validated Chain of Custody
Archer Chain Analytics™ | Mahihkan.com
"""

from pydantic import BaseModel, Field, field_validator
from enum import Enum
from datetime import datetime, timezone
from typing import Optional
import uuid


class FileType(str, Enum):
    TEXT   = "text"
    BINARY = "binary"
    PDF    = "pdf"
    OFFICE = "office"


class LayerStatus(BaseModel):
    hmac_sha256_signing:  bool = False
    sha256_asset_hash:    bool = False
    steganographic_lsb:   bool = False
    pydantic_manifest:    bool = False

    def layers_active(self) -> int:
        return sum([
            self.hmac_sha256_signing,
            self.sha256_asset_hash,
            self.steganographic_lsb,
            self.pydantic_manifest,
        ])

    def label(self) -> str:
        n = self.layers_active()
        return f"{n}/4"


class FingerprintManifest(BaseModel):
    manifest_id:       str       = Field(default_factory=lambda: str(uuid.uuid4()))
    acerbe_version:    str       = Field(default="3.1.0")
    owner_id:          str
    file_name:         str
    file_type:         FileType
    original_size:     int       = Field(..., description="Original file size in bytes")
    output_size:       int       = Field(default=0, description="Fingerprinted output size in bytes")
    asset_hash:        str       = Field(..., description="SHA256 of original asset")
    output_hash:       str       = Field(default="", description="SHA256 of fingerprinted output file")
    hmac_signature:    str       = Field(..., description="HMAC-SHA256 owner signature")
    timestamp:         int       = Field(..., description="Unix UTC timestamp")
    iso_timestamp:     str       = Field(default="")
    short_fingerprint: str
    layer_status:      LayerStatus
    issuing_entity:    str       = Field(default="Archer Chain Analytics™ | Mahihkan.com")
    jurisdiction:      str       = Field(default="Saskatchewan, Canada")
    notes:             Optional[str] = None

    def model_post_init(self, __context) -> None:
        if not self.iso_timestamp:
            object.__setattr__(
                self, "iso_timestamp",
                datetime.fromtimestamp(self.timestamp, tz=timezone.utc).isoformat()
            )

    @field_validator("asset_hash")
    @classmethod
    def validate_hash_length(cls, v: str) -> str:
        if len(v) != 64:
            raise ValueError("asset_hash must be a 64-char SHA256 hex string")
        return v

    def summary(self) -> str:
        return (
            f"AcerbE™ Fingerprint Certificate  [v{self.acerbe_version}]\n"
            f"{'─' * 50}\n"
            f"Manifest ID   : {self.manifest_id}\n"
            f"Owner         : {self.owner_id}\n"
            f"File          : {self.file_name}  ({self.original_size:,} bytes)\n"
            f"Type          : {self.file_type.value.upper()}\n"
            f"Fingerprint   : {self.short_fingerprint}\n"
            f"Asset Hash    : {self.asset_hash[:32]}...\n"
            f"Output Hash   : {self.output_hash[:32]}...\n"
            f"HMAC-SHA256   : {self.hmac_signature[:32]}...\n"
            f"Timestamp     : {self.iso_timestamp}\n"
            f"Layers Active : {self.layer_status.label()}\n"
            f"  [1] HMAC-SHA256 Signing : {'✓' if self.layer_status.hmac_sha256_signing else '✗'}\n"
            f"  [2] SHA256 Asset Hash   : {'✓' if self.layer_status.sha256_asset_hash else '✗'}\n"
            f"  [3] Steganographic LSB  : {'✓' if self.layer_status.steganographic_lsb else '✗'}\n"
            f"  [4] Pydantic Manifest   : {'✓' if self.layer_status.pydantic_manifest else '✗'}\n"
            f"Issuer        : {self.issuing_entity}\n"
            f"Jurisdiction  : {self.jurisdiction}\n"
            f"{'─' * 50}\n"
        )
