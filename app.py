"""Single-use activation keys; deploy this directory as a separate Vercel project."""
from __future__ import annotations

import base64
from datetime import datetime, timezone
from functools import lru_cache
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from sqlalchemy import Column, Integer, MetaData, String, Table, Text, create_engine, select, update
from sqlalchemy.pool import NullPool

metadata = MetaData()
keys = Table("activation_keys", metadata,
    Column("key_hash", String(64), primary_key=True),
    Column("prefix", String(16), nullable=False),
    Column("label", String(160), nullable=False),
    Column("created_at", String(40), nullable=False),
    Column("device_hash", String(64)),
    Column("activated_at", String(40)),
    Column("license_json", Text),
    Column("disabled", Integer, nullable=False, default=0))


@lru_cache
def database():
    url = os.environ["DATABASE_URL"]
    if url.startswith(("postgres://", "postgresql://")):
        url = "postgresql+psycopg://" + url.split("://", 1)[1]
    if os.getenv("VERCEL") and not url.startswith("postgresql+psycopg://"):
        raise RuntimeError("Vercel requires durable PostgreSQL, not local SQLite")
    return create_engine(url, poolclass=NullPool)


def admin(authorization: str = Header(default="")):
    expected = os.environ.get("LICENSE_ADMIN_TOKEN", "")
    if len(expected) < 32:
        raise HTTPException(503, "Set LICENSE_ADMIN_TOKEN (at least 32 characters)")
    if not hmac.compare_digest(authorization, "Bearer " + expected):
        raise HTTPException(401, "Invalid administrator token")


def signing_key():
    return Ed25519PrivateKey.from_private_bytes(
        base64.b64decode(os.environ["LICENSE_SIGNING_KEY"], validate=True))


def now():
    return datetime.now(timezone.utc).isoformat()


class NewKeys(BaseModel):
    count: int = Field(default=1, ge=1, le=100)
    label: str = Field(default="", max_length=160)


class Activation(BaseModel):
    key: str = Field(min_length=20, max_length=160)
    device_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


app = FastAPI(title="DramaClaw activation", docs_url=None, redoc_url=None)


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.get("/", response_class=HTMLResponse)
def dashboard():
    return (Path(__file__).parent / "admin.html").read_text(encoding="utf-8")


@app.get("/healthz")
def health():
    return {"ok": True, "product": "dramaclaw"}


@app.post("/admin/init", dependencies=[Depends(admin)])
def initialize():
    # Explicit setup avoids concurrent DDL during serverless cold starts.
    signing_key()
    metadata.create_all(database())
    return {"ok": True}


@app.post("/admin/keys", dependencies=[Depends(admin)])
def create_keys(body: NewKeys):
    result = []
    with database().begin() as conn:
        for _ in range(body.count):
            raw = "DC-" + secrets.token_hex(24).upper()
            key_hash = hashlib.sha256(raw.encode()).hexdigest()
            conn.execute(keys.insert().values(key_hash=key_hash, prefix=raw[:11],
                label=body.label, created_at=now(), disabled=0))
            result.append(raw)
    return {"keys": result}


@app.get("/admin/keys", dependencies=[Depends(admin)])
def list_keys():
    with database().connect() as conn:
        return {"keys": [dict(row) for row in conn.execute(select(
            keys.c.key_hash, keys.c.prefix, keys.c.label, keys.c.created_at,
            keys.c.activated_at, keys.c.device_hash, keys.c.disabled
        ).order_by(keys.c.created_at.desc()).limit(1000)).mappings()]}


@app.post("/admin/keys/{key_hash}/disable", dependencies=[Depends(admin)])
def disable(key_hash: str):
    with database().begin() as conn:
        changed = conn.execute(update(keys).where(keys.c.key_hash == key_hash,
            keys.c.device_hash.is_(None)).values(disabled=1)).rowcount
    if not changed:
        raise HTTPException(409, "Only unused keys can be disabled; issued licenses work offline")
    return {"ok": True}


@app.post("/v1/activate")
def activate(body: Activation):
    digest = hashlib.sha256(body.key.strip().upper().encode()).hexdigest()
    payload = {"product": "dramaclaw", "version": 1, "license_id": digest,
               "device_hash": body.device_hash, "issued_at": now()}
    encoded = base64.urlsafe_b64encode(json.dumps(payload, sort_keys=True,
        separators=(",", ":")).encode()).decode()
    license_doc = {"payload": encoded,
        "signature": base64.urlsafe_b64encode(signing_key().sign(encoded.encode())).decode()}
    with database().begin() as conn:
        changed = conn.execute(update(keys).where(keys.c.key_hash == digest,
            keys.c.device_hash.is_(None), keys.c.disabled == 0).values(
            device_hash=body.device_hash, activated_at=payload["issued_at"],
            license_json=json.dumps(license_doc))).rowcount
        if changed:
            return license_doc
        row = conn.execute(select(keys).where(keys.c.key_hash == digest)).mappings().first()
        # Lost HTTP responses may be retried by the same machine without consuming another key.
        if row and not row["disabled"] and row["device_hash"] == body.device_hash:
            return json.loads(row["license_json"])
    raise HTTPException(409, "Key is invalid, disabled, or already activated on another machine")
