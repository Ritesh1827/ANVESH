"""Real ECDAT authentication: bcrypt-hashed accounts plus bearer sessions.

Passwords are hashed with bcrypt via passlib (never stored, never logged).
Login issues a random opaque bearer token stored in the database with an
expiry; the token — not the password — authenticates subsequent requests.
"""

from __future__ import annotations

import logging
import re
import secrets
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from passlib.context import CryptContext

from ecdat.persistence import database
from ecdat.persistence.models import SessionRecord, UserRecord

logger = logging.getLogger(__name__)

_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SESSION_TTL_S = 7 * 24 * 60 * 60
MIN_PASSWORD_LEN = 8

_EMAIL_RE = re.compile(r"^\S+@\S+\.\S+$")


class AuthError(ValueError):
    """Raised for invalid credentials, duplicates, or bad input."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def normalise_email(email: str) -> str:
    cleaned = email.strip().lower()
    if not _EMAIL_RE.match(cleaned):
        raise AuthError("Enter a valid email address.")
    return cleaned


def validate_password(password: str) -> str:
    if len(password) < MIN_PASSWORD_LEN:
        raise AuthError("Password must be at least 8 characters.")
    return password


def hash_password(password: str) -> str:
    return _pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _pwd_context.verify(password, password_hash)
    except Exception:  # noqa: BLE001 — a bad hash verifies as False
        return False


class AuthStore:
    """User and session persistence backed by the configured database."""

    def __init__(self) -> None:
        self._lock = threading.Lock()

    def _ensure_tables(self) -> None:
        try:
            with database.session() as session:
                session.execute(UserRecord.__table__.select().limit(1))
        except Exception:
            database.init_db_sync()

    def register(self, email: str, password: str) -> dict:
        cleaned = normalise_email(email)
        validate_password(password)
        self._ensure_tables()
        user_id = uuid.uuid4().hex
        with database.session() as session:
            existing = (
                session.query(UserRecord).filter(UserRecord.email == cleaned).one_or_none()
            )
            if existing is not None:
                raise AuthError("An account with this email already exists.")
            session.add(UserRecord(
                id=user_id,
                email=cleaned,
                password_hash=hash_password(password),
                created_at=_now(),
            ))
            session.commit()
        logger.info("Registered user %s", cleaned)
        return {"user_id": user_id, "email": cleaned}

    def login(self, email: str, password: str) -> dict:
        cleaned = normalise_email(email)
        self._ensure_tables()
        with database.session() as session:
            user = (
                session.query(UserRecord).filter(UserRecord.email == cleaned).one_or_none()
            )
            if user is None or not verify_password(password, user.password_hash):
                raise AuthError("Invalid email or password.")
            token = secrets.token_hex(32)
            now = _now()
            session.add(SessionRecord(
                token=token,
                user_id=user.id,
                created_at=now,
                expires_at=now + timedelta(seconds=SESSION_TTL_S),
            ))
            session.commit()
            return {
                "token": token,
                "user_id": user.id,
                "email": user.email,
                "expires_at": (now + timedelta(seconds=SESSION_TTL_S)).isoformat(),
            }

    def logout(self, token: str) -> None:
        with database.session() as session:
            session.query(SessionRecord).filter(SessionRecord.token == token).delete()
            session.commit()

    def get_user_by_token(self, token: Optional[str]) -> Optional[dict]:
        if not token:
            return None
        with database.session() as session:
            record = session.get(SessionRecord, token)
            if record is None:
                return None
            expiry = record.expires_at
            aware = expiry if expiry.tzinfo else expiry.replace(tzinfo=timezone.utc)
            if aware <= _now():
                session.delete(record)
                session.commit()
                return None
            user = session.get(UserRecord, record.user_id)
            if user is None:
                return None
            return {"user_id": user.id, "email": user.email}

    def get_user(self, user_id: str) -> Optional[dict]:
        with database.session() as session:
            user = session.get(UserRecord, user_id)
            if user is None:
                return None
            return {"user_id": user.id, "email": user.email}
