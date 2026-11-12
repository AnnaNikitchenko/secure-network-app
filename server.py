"""Secure JSON TCP/TLS service used by the practical assignment."""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import json
import os
import secrets
import shutil
import ssl
import struct
import time
from pathlib import Path
from typing import Any

import bcrypt
import jwt
import pyotp
from dotenv import load_dotenv

from generate_cert import generate

BASE = Path(__file__).resolve().parent
load_dotenv(BASE / ".env")
MAX_MESSAGE = 1024 * 1024
TIMEOUT = 30
DB_FILE = Path(os.getenv("APP_DB", BASE / "data" / "users.sqlite3"))
LOG_FILE = Path(os.getenv("APP_LOG", BASE / "logs" / "server.jsonl"))
JWT_SECRET = os.getenv("JWT_SECRET", "")
JWT_TTL = int(os.getenv("JWT_TTL_SECONDS", "900"))
LOCK_ATTEMPTS = int(os.getenv("LOCK_ATTEMPTS", "5"))
LOCK_SECONDS = int(os.getenv("LOCK_SECONDS", "300"))
_failures: dict[str, tuple[int, float]] = {}
_mfa_challenges: dict[str, tuple[str, float]] = {}


def _db():
    import sqlite3
    DB_FILE.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_FILE, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("""CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY, password_hash BLOB NOT NULL, role TEXT NOT NULL
        CHECK(role IN ('USER','ADMIN')), mfa_secret TEXT, mfa_enabled INTEGER NOT NULL DEFAULT 0,
        last_otp_counter INTEGER NOT NULL DEFAULT -1)""")
    db.execute("""CREATE TABLE IF NOT EXISTS revoked_tokens (
        jti TEXT PRIMARY KEY, expires INTEGER NOT NULL)""")
    db.commit()
    return db


def create_user(username: str, password: str, role: str = "USER") -> None:
    if not username or len(username) > 64 or any(c.isspace() for c in username):
        raise ValueError("Некоректний логін")
    if len(password) < 12:
        raise ValueError("Пароль має містити щонайменше 12 символів")
    if len(password.encode("utf-8")) > 72:
        raise ValueError("Пароль має вкладатися у 72 байти, обмеження bcrypt")
    if role not in {"USER", "ADMIN"}:
        raise ValueError("Невідома роль")
    with _db() as db:
        db.execute("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
                   (username, bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)), role))


def login_lock_remaining(key: str, now: float | None = None) -> int:
    """Return rounded-up lock seconds for an IP/account pair, or zero."""
    now = time.monotonic() if now is None else now
    _, until = _failures.get(key, (0, 0))
    return max(0, int(until - now + 0.999))


def record_login_failure(key: str, now: float | None = None) -> tuple[bool, int]:
    """Record an attempt and return (locked, attempts_left)."""
    now = time.monotonic() if now is None else now
    count, until = _failures.get(key, (0, 0))
    if now < until:
        return True, 0
    count += 1
    if count >= LOCK_ATTEMPTS:
        _failures[key] = (0, now + LOCK_SECONDS)
        return True, 0
    _failures[key] = (count, 0)
    return False, max(0, LOCK_ATTEMPTS - count)


def log_event(event: str, **fields: Any) -> None:
    """Write allow-listed event fields, never secrets or arbitrary payloads."""
    allowed = {k: v for k, v in fields.items()
               if k in {"user", "ip", "status", "code", "reason", "bytes", "tls_version", "cipher", "role"}}
    record = {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": event, **allowed}
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


async def receive(reader: asyncio.StreamReader) -> dict[str, Any]:
    size = struct.unpack("!I", await asyncio.wait_for(reader.readexactly(4), TIMEOUT))[0]
    if not 1 <= size <= MAX_MESSAGE:
        raise ValueError("invalid_message_size")
    obj = json.loads((await asyncio.wait_for(reader.readexactly(size), TIMEOUT)).decode("utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("message_must_be_object")
    return obj


async def send(writer: asyncio.StreamWriter, obj: dict[str, Any]) -> None:
    raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode()
    if len(raw) > MAX_MESSAGE:
        raise ValueError("response_too_large")
    writer.write(struct.pack("!I", len(raw)) + raw)
    await asyncio.wait_for(writer.drain(), TIMEOUT)


def _mint_token(username: str, role: str) -> str:
    if len(JWT_SECRET.encode()) < 32:
        raise RuntimeError("JWT_SECRET має містити щонайменше 32 байти")
    now = int(time.time())
    return jwt.encode({"sub": username, "role": role, "iat": now, "exp": now + JWT_TTL,
                       "jti": secrets.token_urlsafe(18)}, JWT_SECRET, algorithm="HS256")


def _decode_token(token: str) -> dict[str, Any] | None:
    try:
        claims = jwt.decode(token, JWT_SECRET, algorithms=["HS256"],
                            options={"require": ["sub", "role", "exp", "jti"]})
        if claims["role"] not in {"USER", "ADMIN"}:
            return None
        with _db() as db:
            if db.execute("SELECT 1 FROM revoked_tokens WHERE jti=?", (claims["jti"],)).fetchone():
                return None
        return claims
    except (jwt.InvalidTokenError, KeyError, RuntimeError):
        return None


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername")
    ip = str(peer[0]) if peer else None
    tls = writer.get_extra_info("ssl_object")
    version = tls.version() if tls else None
    cipher = tls.cipher()[0] if tls and tls.cipher() else None
    user = None
    pending_mfa: str | None = None
    log_event("connection.success", ip=ip, status="success", code=200, tls_version=version, cipher=cipher)
    try:
        while True:
            try:
                msg = await receive(reader)
            except asyncio.IncompleteReadError:
                break
            except (asyncio.TimeoutError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                log_event("message.invalid", ip=ip, user=user, status="failure", code=400, reason=type(exc).__name__)
                await send(writer, {"ok": False, "error": "invalid_message"})
                continue
            op = msg.get("op")
            if not tls and op not in {"ping", "echo"}:
                await send(writer, {"ok": False, "error": "secure_transport_required"})
                continue
            if op == "register":
                try:
                    create_user(str(msg.get("username", "")), str(msg.get("password", "")))
                    await send(writer, {"ok": True, "message": "account_created"})
                except (ValueError, Exception) as exc:
                    # Do not reveal database details to a remote client.
                    log_event("auth.register_failure", user=msg.get("username"), ip=ip, status="failure", code=400, reason=type(exc).__name__)
                    await send(writer, {"ok": False, "error": "registration_failed"})
                continue
            if op == "auth":
                name, password = msg.get("username"), msg.get("password")
                key = f"{ip}:{name}"
                now = time.monotonic()
                retry_after = login_lock_remaining(key, now)
                if retry_after:
                    log_event("auth.locked", ip=ip, user=name, status="failure", code=429, reason="temporary_lock")
                    await send(writer, {"ok": False, "error": "temporarily_locked", "retry_after": retry_after})
                    continue
                with _db() as db:
                    record = db.execute("SELECT * FROM users WHERE username=?", (name,)).fetchone() if isinstance(name, str) else None
                valid = bool(record and isinstance(password, str) and len(password.encode("utf-8")) <= 72
                             and bcrypt.checkpw(password.encode(), record["password_hash"]))
                if not valid:
                    locked, attempts_left = record_login_failure(key, now)
                    if locked:
                        log_event("auth.locked", ip=ip, user=name, status="failure", code=429, reason="attempt_limit")
                    log_event("auth.failure", ip=ip, user=name, status="failure", code=401, reason="invalid_credentials")
                    await send(writer, {"ok": False, "error": "invalid_credentials", "attempts_left": attempts_left})
                    continue
                _failures.pop(key, None)
                user = name
                if record["mfa_enabled"]:
                    now = time.monotonic()
                    for stale, (_, deadline) in list(_mfa_challenges.items()):
                        if deadline <= now:
                            _mfa_challenges.pop(stale, None)
                    pending_mfa = secrets.token_urlsafe(24)
                    _mfa_challenges[pending_mfa] = (name, now + 120)
                    log_event("mfa.challenge", user=name, ip=ip, status="success", code=202)
                    await send(writer, {"ok": True, "mfa_required": True, "challenge": pending_mfa})
                else:
                    token = _mint_token(name, record["role"])
                    log_event("auth.success", user=name, ip=ip, role=record["role"], status="success", code=200)
                    await send(writer, {"ok": True, "token": token, "role": record["role"]})
                continue
            if op == "mfa_verify":
                challenge = msg.get("challenge")
                challenge_record = _mfa_challenges.pop(challenge, None) if isinstance(challenge, str) else None
                pending_mfa = challenge_record[0] if challenge_record else None
                if not challenge_record or challenge_record[1] < time.monotonic():
                    await send(writer, {"ok": False, "error": "invalid_mfa_challenge"}); continue
                code = msg.get("otp")
                with _db() as db:
                    record = db.execute("SELECT * FROM users WHERE username=?", (pending_mfa,)).fetchone()
                    secret = record["mfa_secret"] if record else None
                    counter = int(time.time()) // 30
                    valid_counter = next((c for c in (counter-1, counter, counter+1)
                                          if c > record["last_otp_counter"] and pyotp.TOTP(secret).verify(str(code), for_time=c*30, valid_window=0)), None) if record and secret else None
                    if valid_counter is not None:
                        db.execute("UPDATE users SET last_otp_counter=? WHERE username=?", (valid_counter, pending_mfa))
                if valid_counter is None:
                    log_event("mfa.failure", user=pending_mfa, ip=ip, status="failure", code=401, reason="invalid_or_reused_otp")
                    await send(writer, {"ok": False, "error": "invalid_otp"})
                else:
                    token = _mint_token(pending_mfa, record["role"])
                    user = pending_mfa
                    log_event("mfa.success", user=user, ip=ip, status="success", code=200)
                    await send(writer, {"ok": True, "token": token, "role": record["role"]})
                    pending_mfa = None
                continue
            if op == "mfa_enroll":
                claims = _decode_token(str(msg.get("token", "")))
                if not claims:
                    log_event("token.invalid", ip=ip, user=user, status="failure", code=401, reason="invalid_token")
                    await send(writer, {"ok": False, "error": "invalid_token"}); continue
                secret = pyotp.random_base32()
                with _db() as db:
                    record = db.execute("SELECT mfa_enabled FROM users WHERE username=?", (claims["sub"],)).fetchone()
                    if not record or record["mfa_enabled"]:
                        await send(writer, {"ok": False, "error": "mfa_already_enabled" if record else "user_not_found"})
                        continue
                    db.execute("UPDATE users SET mfa_secret=? WHERE username=?", (secret, claims["sub"]))
                uri = pyotp.TOTP(secret).provisioning_uri(claims["sub"], issuer_name="Secure Network App")
                log_event("mfa.enrollment_started", user=claims["sub"], ip=ip, status="success", code=200)
                await send(writer, {"ok": True, "secret": secret, "otpauth_uri": uri}); continue
            if op == "mfa_enable" or op == "mfa_disable":
                claims = _decode_token(str(msg.get("token", "")))
                if not claims:
                    await send(writer, {"ok": False, "error": "invalid_token"}); continue
                with _db() as db:
                    record = db.execute("SELECT * FROM users WHERE username=?", (claims["sub"],)).fetchone()
                    counter = int(time.time()) // 30
                    good_counter = next((c for c in (counter-1,counter,counter+1)
                                         if record and record["mfa_secret"] and c > record["last_otp_counter"]
                                         and pyotp.TOTP(record["mfa_secret"]).verify(str(msg.get("otp", "")), for_time=c*30)), None)
                    good = good_counter is not None
                    if good:
                        db.execute("UPDATE users SET mfa_enabled=?,last_otp_counter=? WHERE username=?", (1 if op == "mfa_enable" else 0, good_counter, claims["sub"]))
                if not good:
                    log_event("mfa.failure", user=claims["sub"], ip=ip, status="failure", code=401, reason="invalid_otp")
                    await send(writer, {"ok": False, "error": "invalid_otp"})
                else:
                    log_event("mfa.enabled" if op == "mfa_enable" else "mfa.disabled", user=claims["sub"], ip=ip, status="success", code=200)
                    await send(writer, {"ok": True})
                continue
            if op == "ping" and not tls:
                await send(writer, {"ok": True, "reply": "PONG"}); continue
            if op == "echo" and not tls:
                text = msg.get("text")
                if not isinstance(text, str): await send(writer, {"ok": False, "error": "invalid_text"})
                else: await send(writer, {"ok": True, "reply": text})
                continue
            token = str(msg.get("token", ""))
            claims = _decode_token(token) if token else None
            if not claims:
                log_event("access.denied" if token else "access.unauthorized", user=user, ip=ip, status="failure", code=401, reason="missing_or_invalid_token")
                await send(writer, {"ok": False, "error": "authentication_required" if not token else "invalid_token"}); continue
            user = claims["sub"]
            if op == "logout":
                with _db() as db:
                    db.execute("INSERT OR IGNORE INTO revoked_tokens(jti,expires) VALUES(?,?)", (claims["jti"], claims["exp"]))
                    db.execute("DELETE FROM revoked_tokens WHERE expires < ?", (int(time.time()),))
                await send(writer, {"ok": True, "message": "session_closed"}); break
            if op == "data":
                payload, digest = msg.get("payload"), msg.get("sha256")
                actual = hashlib.sha256(payload.encode()).hexdigest() if isinstance(payload, str) else ""
                if not isinstance(digest, str) or not hmac.compare_digest(actual, digest.lower()):
                    log_event("integrity.failure", ip=ip, user=user, status="failure", code=422, reason="sha256_mismatch")
                    await send(writer, {"ok": False, "error": "integrity_check_failed"})
                else:
                    log_event("data.success", ip=ip, user=user, status="success", code=200, bytes=len(payload.encode()))
                    await send(writer, {"ok": True, "sha256": actual, "bytes": len(payload.encode())})
                continue
            if op == "admin_status":
                if claims.get("role") != "ADMIN":
                    log_event("access.denied", ip=ip, user=user, status="failure", code=403, reason="admin_required")
                    await send(writer, {"ok": False, "error": "forbidden"})
                else:
                    await send(writer, {"ok": True, "message": "admin_access_granted"})
                continue
            if op == "admin_list_users":
                if claims.get("role") != "ADMIN":
                    log_event("access.denied", ip=ip, user=user, status="failure", code=403, reason="admin_required")
                    await send(writer, {"ok": False, "error": "forbidden"})
                else:
                    with _db() as db:
                        users = [dict(row) for row in db.execute("SELECT username,role,mfa_enabled FROM users ORDER BY username")]
                    await send(writer, {"ok": True, "users": users})
                continue
            await send(writer, {"ok": False, "error": "unsupported_operation"})
    except (ConnectionError, asyncio.TimeoutError, ssl.SSLError, OSError) as exc:
        log_event("connection.error", ip=ip, user=user, status="failure", code=500, reason=type(exc).__name__)
    except Exception as exc:
        log_event("server.error", ip=ip, user=user, status="failure", code=500, reason=type(exc).__name__)
    finally:
        writer.close()
        try: await writer.wait_closed()
        except (ConnectionError, OSError): pass
        log_event("session.closed", ip=ip, user=user, status="success", code=200)


def make_server_context(cert: str, key: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    return ctx


async def run_server(host: str, port: int, cert: str, key: str, plaintext: bool = False) -> None:
    context = None if plaintext else make_server_context(cert, key)
    srv = await asyncio.start_server(handle, host, port, ssl=context, limit=MAX_MESSAGE + 4, ssl_handshake_timeout=TIMEOUT if context else None)
    print(f"{'DEMO TCP' if plaintext else 'TLS'} server listening on {host}:{port}")
    async with srv: await srv.serve_forever()


def main() -> None:
    p = argparse.ArgumentParser(description="TLS/TCP secure network server")
    p.add_argument("--host", default=os.getenv("SERVER_HOST", "127.0.0.1"))
    p.add_argument("--port", type=int, default=int(os.getenv("SERVER_PORT", "8443")))
    p.add_argument("--cert", default=os.getenv("TLS_CERT", str(BASE / "data" / "server.crt")))
    p.add_argument("--key", default=os.getenv("TLS_KEY", str(BASE / "data" / "server.key")))
    p.add_argument("--demo-plaintext", action="store_true", help="Unsafe PING/ECHO demonstration only")
    args = p.parse_args()
    if not args.demo_plaintext and len(JWT_SECRET.encode("utf-8")) < 32:
        p.error("Налаштуйте JWT_SECRET довжиною щонайменше 32 байти у .env")
    if JWT_TTL < 1 or LOCK_ATTEMPTS < 1 or LOCK_SECONDS < 1:
        p.error("JWT_TTL_SECONDS, LOCK_ATTEMPTS і LOCK_SECONDS мають бути додатними")
    if not args.demo_plaintext:
        cert_path, key_path = Path(args.cert), Path(args.key)
        if cert_path.is_file() != key_path.is_file():
            p.error("TLS_CERT і TLS_KEY мають існувати разом; не перезаписую неповну пару")
        if not cert_path.is_file():
            cert, key = generate(cert_path.parent)
            args.cert, args.key = str(cert), str(key)
        ca_path = cert_path.parent / "ca.crt"
        if not ca_path.exists():
            # Backward compatibility for the earlier self-signed server cert.
            shutil.copyfile(cert_path, ca_path)
    asyncio.run(run_server(args.host, args.port, args.cert, args.key, args.demo_plaintext))


if __name__ == "__main__": main()
