import hashlib
import os
import secrets
from dataclasses import dataclass
from datetime import timedelta, timezone

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from fastapi import Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session as DBSession

from .db import Audit, Enrollment, Session, User, get_db, now
from .secrets import decrypt_totp


hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
COOKIE_NAME = "satellite_session"


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def aware(value):
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def audit(db: DBSession, actor: str | None, action: str, target: str | None = None,
          project: str | None = None, outcome: str = "success", details: dict | None = None):
    db.add(Audit(actor_id=actor, action=action, target_id=target, project_id=project,
                 outcome=outcome, details=details or {}))


def issue_enrollment(db: DBSession, user: User) -> str:
    for previous in db.scalars(select(Enrollment).where(Enrollment.user_id == user.id, Enrollment.used_at.is_(None))):
        previous.used_at = now()
    token = secrets.token_urlsafe(32)
    db.add(Enrollment(token_hash=digest(token), user_id=user.id, expires_at=now() + timedelta(hours=24)))
    return token


def enroll(db: DBSession, token: str, password: str, code: str):
    entry = db.get(Enrollment, digest(token))
    if not entry or entry.used_at or aware(entry.expires_at) < now():
        raise HTTPException(400, "Invalid or expired enrollment token")
    user = db.get(User, entry.user_id)
    if not user or not user.totp_secret or not pyotp.TOTP(decrypt_totp(user.totp_secret)).verify(code, valid_window=1):
        raise HTTPException(400, "Invalid authenticator code")
    if len(password) < 12 or len(password) > 128:
        raise HTTPException(422, "Password must contain 12 to 128 characters")
    user.password_hash = hasher.hash(password)
    user.active = True
    user.failed_logins = 0
    entry.used_at = now()
    codes = [secrets.token_hex(8) for _ in range(10)]
    user.recovery_hashes = [digest(code) for code in codes]
    audit(db, user.id, "account.enroll", user.id)
    db.commit()
    return codes


def verify_factor(user: User, code: str) -> bool:
    if code.startswith("recovery:"):
        value = digest(code.removeprefix("recovery:"))
        if value in user.recovery_hashes:
            user.recovery_hashes = [x for x in user.recovery_hashes if x != value]
            return True
        return False
    if not user.totp_secret:
        return False
    totp = pyotp.TOTP(decrypt_totp(user.totp_secret))
    for step in range(totp.timecode(now()) - 1, totp.timecode(now()) + 2):
        if step > user.last_totp_step and secrets.compare_digest(totp.at(step * 30), code):
            user.last_totp_step = step
            return True
    return False


def login(db: DBSession, email: str, password: str, code: str, response: Response):
    user = db.scalar(select(User).where(User.email == email.lower().strip()))
    if not user or not user.active or not user.password_hash or (user.locked_until and aware(user.locked_until) > now()):
        audit(db, user.id if user else None, "auth.login", outcome="failure")
        db.commit()
        raise HTTPException(401, "Invalid credentials")
    try:
        valid_password = hasher.verify(user.password_hash, password)
    except VerificationError:
        valid_password = False
    if not valid_password or not verify_factor(user, code):
        user.failed_logins += 1
        if user.failed_logins >= 5:
            user.locked_until = now() + timedelta(minutes=15)
            user.failed_logins = 0
        audit(db, user.id, "auth.login", user.id, outcome="failure")
        db.commit()
        raise HTTPException(401, "Invalid credentials")
    user.failed_logins = 0
    user.locked_until = None
    raw = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    db.add(Session(token_hash=digest(raw), user_id=user.id, csrf_token=csrf))
    audit(db, user.id, "auth.login", user.id)
    db.commit()
    response.set_cookie(COOKIE_NAME, raw, httponly=True, secure=os.getenv("COOKIE_SECURE", "false").lower() == "true",
                        samesite="strict", max_age=12 * 3600, path="/")
    return {"user": public_user(user), "csrf_token": csrf}


def public_user(user: User):
    return {"id": user.id, "email": user.email, "name": user.name, "is_admin": user.is_admin, "active": user.active}


@dataclass
class Actor:
    user: User
    session: Session


def current_actor(request: Request, db: DBSession = Depends(get_db)) -> Actor:
    raw = request.cookies.get(COOKIE_NAME)
    session = db.get(Session, digest(raw)) if raw else None
    if not session or session.revoked_at or aware(session.created_at) + timedelta(hours=12) < now() or aware(session.last_seen_at) + timedelta(minutes=30) < now():
        raise HTTPException(401, "Authentication required")
    user = db.get(User, session.user_id)
    if not user or not user.active:
        raise HTTPException(401, "Authentication required")
    if request.method not in {"GET", "HEAD", "OPTIONS"} and not secrets.compare_digest(request.headers.get("X-CSRF-Token", ""), session.csrf_token):
        raise HTTPException(403, "Invalid CSRF token")
    session.last_seen_at = now()
    db.commit()
    return Actor(user, session)


def require_admin(actor: Actor):
    if not actor.user.is_admin:
        raise HTTPException(403, "Admin role required")


def revoke_user_sessions(db: DBSession, user_id: str):
    for session in db.scalars(select(Session).where(Session.user_id == user_id, Session.revoked_at.is_(None))):
        session.revoked_at = now()
