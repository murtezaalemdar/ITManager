from __future__ import annotations

import secrets
from typing import Optional

from fastapi import Request
from passlib.context import CryptContext
from sqlalchemy import select

from .db import SessionLocal
from .models import User
from .settings import settings

# bcrypt backend'i bazı sürümlerde (bcrypt>=4) passlib 1.7.4 ile uyumsuz olabiliyor.
# Daha stabil olması için pbkdf2_sha256 kullanıyoruz.
pwd = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


def hash_password(p: str) -> str:
    return pwd.hash(p)


def verify_password(p: str, h: str) -> bool:
    return pwd.verify(p, h)


def get_sso_user(request: Request) -> Optional[str]:
    header_name = settings.sso_header_name
    value = request.headers.get(header_name)
    value = value.strip() if value else ""
    return value or None


def ensure_default_admin() -> None:
    with SessionLocal() as db:
        existing = db.scalar(select(User).limit(1))
        if existing:
            return
        # Default admin credentials (change immediately)
        u = User(username="admin", password_hash=hash_password("admin"), is_admin=True)
        db.add(u)
        db.commit()


def generate_device_token() -> str:
    return secrets.token_urlsafe(32)
