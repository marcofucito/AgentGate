import hashlib
import io
import os
import secrets
import tarfile
from datetime import datetime, timezone
from typing import Optional

import paramiko
from cryptography.fernet import Fernet
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, create_engine, func
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker
from starlette.middleware.sessions import SessionMiddleware


DATABASE_URL = os.getenv("AGENTGATE_DATABASE_URL", "sqlite:///./agentgate.db")
BASE_URL = os.getenv("AGENTGATE_BASE_URL", "http://localhost:8000")
MAGIC_LOGIN_TOKEN = os.getenv("AGENTGATE_MAGIC_TOKEN", "")
SECRET_KEY = os.getenv("AGENTGATE_SECRET_KEY", secrets.token_urlsafe(32))
MASTER_KEY = os.getenv("AGENTGATE_MASTER_KEY")
if not MASTER_KEY:
    MASTER_KEY = Fernet.generate_key().decode()
    print(f"Generated dev AGENTGATE_MASTER_KEY={MASTER_KEY}")

fernet = Fernet(MASTER_KEY.encode())
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))


class ServerTarget(Base):
    __tablename__ = "servers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    host: Mapped[str] = mapped_column(String(255))
    port: Mapped[int] = mapped_column(Integer, default=22)
    username: Mapped[str] = mapped_column(String(120))
    auth_type: Mapped[str] = mapped_column(String(30), default="password")
    encrypted_password: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    encrypted_private_key: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    default_policy: Mapped[str] = mapped_column(String(30), default="allow_all")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    rules: Mapped[list["CommandRule"]] = relationship(back_populates="server", cascade="all, delete-orphan")


class CommandRule(Base):
    __tablename__ = "command_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    server_id: Mapped[int] = mapped_column(ForeignKey("servers.id"))
    type: Mapped[str] = mapped_column(String(10))
    pattern: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    server: Mapped[ServerTarget] = relationship(back_populates="rules")


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    key_hash: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    key_prefix: Mapped[str] = mapped_column(String(32))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    api_key_id: Mapped[Optional[int]] = mapped_column(ForeignKey("api_keys.id"), nullable=True)
    server_id: Mapped[Optional[int]] = mapped_column(ForeignKey("servers.id"), nullable=True)
    command: Mapped[str] = mapped_column(Text)
    decision: Mapped[str] = mapped_column(String(20))
    reason: Mapped[str] = mapped_column(Text, default="")
    stdout_preview: Mapped[str] = mapped_column(Text, default="")
    stderr_preview: Mapped[str] = mapped_column(Text, default="")
    exit_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))


app = FastAPI(title="AgentGate")
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")


def hash_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def encrypt(value: str | None) -> Optional[str]:
    if not value:
        return None
    return fernet.encrypt(value.encode()).decode()


def decrypt(value: str | None) -> Optional[str]:
    if not value:
        return None
    return fernet.decrypt(value.encode()).decode()


def db_session():
    with SessionLocal() as db:
        yield db


def get_db() -> Session:
    return SessionLocal()


def password_hash(password: str) -> str:
    return hash_text(f"agentgate:{password}")


def require_user(request: Request):
    if not request.session.get("user_id"):
        return RedirectResponse("/login", status_code=303)
    return None


def current_api_key(request: Request, db: Session) -> ApiKey:
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = auth.split(" ", 1)[1].strip()
    api_key = db.query(ApiKey).filter(ApiKey.key_hash == hash_text(token), ApiKey.revoked.is_(False)).first()
    if not api_key:
        raise HTTPException(status_code=401, detail="Invalid API key")
    api_key.last_used_at = datetime.now(timezone.utc)
    db.commit()
    return api_key


def is_command_allowed(command: str, allowed_patterns: list[str], denied_patterns: list[str], default_policy: str):
    normalized = command.lower()
    for pattern in denied_patterns:
        if pattern.lower() in normalized:
            return False, f"Command matched denied pattern: {pattern}"
    if default_policy == "allow_all":
        return True, "Allowed by default policy allow_all"
    for pattern in allowed_patterns:
        lowered = pattern.lower()
        if normalized.startswith(lowered) or lowered in normalized:
            return True, f"Command matched allowed pattern: {pattern}"
    return False, "Denied by default policy deny_all"


def run_ssh(server: ServerTarget, command: str):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = {
        "hostname": server.host,
        "port": server.port,
        "username": server.username,
        "timeout": 8,
        "banner_timeout": 8,
        "auth_timeout": 8,
    }
    if server.auth_type == "private_key":
        from io import StringIO

        key_text = decrypt(server.encrypted_private_key)
        kwargs["pkey"] = paramiko.RSAKey.from_private_key(StringIO(key_text))
    else:
        kwargs["password"] = decrypt(server.encrypted_password)
    client.connect(**kwargs)
    stdin, stdout, stderr = client.exec_command(command, timeout=20)
    out = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace")
    exit_code = stdout.channel.recv_exit_status()
    client.close()
    return out, err, exit_code


def create_audit(db: Session, api_key_id, server_id, command, decision, reason="", stdout="", stderr="", exit_code=None):
    audit = AuditLog(
        api_key_id=api_key_id,
        server_id=server_id,
        command=command,
        decision=decision,
        reason=reason,
        stdout_preview=stdout[:4000],
        stderr_preview=stderr[:4000],
        exit_code=exit_code,
    )
    db.add(audit)
    db.commit()
    db.refresh(audit)
    return audit


def operation_summary(command: str) -> str:
    normalized = " ".join(command.lower().split())
    checks = [
        (["apt-get", "install", "docker"], "Install Docker"),
        (["docker.io", "install"], "Install Docker"),
        (["apt-get", "purge", "docker"], "Uninstall Docker"),
        (["apt-get", "remove", "docker"], "Uninstall Docker"),
        (["nuking /var/lib/docker"], "Uninstall Docker"),
        (["apt-get", "install", "python3"], "Install Python 3"),
        (["python3 --version"], "Verify Python 3"),
        (["docker --version"], "Verify Docker"),
        (["free", "/mem:"], "Check memory usage"),
        (["df", "-h"], "Check disk usage"),
        (["uptime"], "Check uptime"),
        (["systemctl", "nginx"], "Check nginx service"),
        (["service", "nginx", "status"], "Check nginx service"),
        (["whoami", "hostname"], "Connection identity check"),
        (["apt-get", "update"], "Update package index"),
        (["systemctl", "enable"], "Enable service"),
        (["systemctl", "stop"], "Stop service"),
        (["systemctl", "start"], "Start service"),
        (["rm -rf"], "Destructive file removal attempt"),
        (["cat /etc/shadow"], "Sensitive file access attempt"),
    ]
    for tokens, label in checks:
        if all(token in normalized for token in tokens):
            return label
    if normalized.startswith("sudo "):
        return "Privileged shell command"
    if normalized.startswith(("apt ", "apt-get ")):
        return "Package management"
    if normalized.startswith(("systemctl ", "service ")):
        return "Service management"
    return "Shell command"


def audit_actor(log: AuditLog, keys_by_id: dict[int, ApiKey]) -> str:
    key = keys_by_id.get(log.api_key_id) if log.api_key_id else None
    if key:
        return f"{key.name} ({key.key_prefix}...)"
    return "Dashboard user"


def build_audit_rows(logs: list[AuditLog], servers_by_id: dict[int, ServerTarget], keys_by_id: dict[int, ApiKey]):
    rows = []
    for log in logs:
        rows.append(
            {
                "log": log,
                "server": servers_by_id.get(log.server_id) if log.server_id else None,
                "actor": audit_actor(log, keys_by_id),
                "operation": operation_summary(log.command),
            }
        )
    return rows


def build_server_reviews(rows):
    reviews = {}
    for row in rows:
        server = row["server"]
        if not server:
            continue
        review = reviews.setdefault(
            server.id,
            {
                "server": server,
                "total": 0,
                "allowed": 0,
                "denied": 0,
                "error": 0,
                "operations": {},
            },
        )
        log = row["log"]
        review["total"] += 1
        if log.decision in ("allowed", "denied", "error"):
            review[log.decision] += 1
        operation = review["operations"].setdefault(
            row["operation"],
            {
                "name": row["operation"],
                "count": 0,
                "last_actor": row["actor"],
                "last_decision": log.decision,
                "last_time": log.created_at,
                "last_command": log.command,
            },
        )
        operation["count"] += 1
    for review in reviews.values():
        review["operations"] = sorted(review["operations"].values(), key=lambda item: item["last_time"], reverse=True)
    return sorted(reviews.values(), key=lambda item: item["server"].name.lower())


@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)
    db = get_db()
    try:
        if not db.query(User).filter_by(email="admin@example.com").first():
            db.add(User(email="admin@example.com", password_hash=password_hash("hackrome")))
        if db.query(ServerTarget).count() == 0:
            demo = ServerTarget(
                name="web-demo",
                host="demo-ssh",
                port=22,
                username="demo",
                auth_type="password",
                encrypted_password=encrypt("demo"),
                default_policy="allow_all",
            )
            db.add(demo)
            db.flush()
            for pattern in ["rm -rf", "shutdown", "reboot", "mkfs", "dd if=", "cat /etc/shadow"]:
                db.add(CommandRule(server_id=demo.id, type="deny", pattern=pattern))
        db.commit()
    finally:
        db.close()


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    if not request.session.get("user_id"):
        return RedirectResponse("/login", status_code=303)
    db = get_db()
    try:
        stats = {
            "servers": db.query(ServerTarget).count(),
            "api_keys": db.query(ApiKey).filter(ApiKey.revoked.is_(False)).count(),
            "commands": db.query(AuditLog).count(),
            "denied": db.query(AuditLog).filter(AuditLog.decision == "denied").count(),
        }
        recent = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(6).all()
        servers_by_id = {s.id: s for s in db.query(ServerTarget).all()}
        keys_by_id = {k.id: k for k in db.query(ApiKey).all()}
        recent_rows = build_audit_rows(recent, servers_by_id, keys_by_id)
        return templates.TemplateResponse("dashboard.html", {"request": request, "stats": stats, "recent": recent_rows})
    finally:
        db.close()


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.get("/magic/{token}")
async def magic_login(request: Request, token: str):
    if not MAGIC_LOGIN_TOKEN or not secrets.compare_digest(token, MAGIC_LOGIN_TOKEN):
        raise HTTPException(status_code=404, detail="Not found")
    db = get_db()
    try:
        user = db.query(User).filter_by(email="admin@example.com").first()
        if not user:
            raise HTTPException(status_code=404, detail="Not found")
        request.session["user_id"] = user.id
        return RedirectResponse("/", status_code=303)
    finally:
        db.close()


@app.post("/login", response_class=HTMLResponse)
async def login(request: Request):
    form = await request.form()
    db = get_db()
    try:
        user = db.query(User).filter_by(email=form.get("email")).first()
        if not user or user.password_hash != password_hash(form.get("password", "")):
            return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"}, status_code=401)
        request.session["user_id"] = user.id
        return RedirectResponse("/", status_code=303)
    finally:
        db.close()


@app.post("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@app.get("/servers", response_class=HTMLResponse)
async def servers(request: Request):
    redirect = require_user(request)
    if redirect:
        return redirect
    db = get_db()
    try:
        items = db.query(ServerTarget).order_by(ServerTarget.name).all()
        return templates.TemplateResponse("servers.html", {"request": request, "servers": items})
    finally:
        db.close()


@app.get("/servers/new", response_class=HTMLResponse)
async def new_server(request: Request):
    redirect = require_user(request)
    if redirect:
        return redirect
    return templates.TemplateResponse("server_form.html", {"request": request, "server": None, "error": None})


@app.post("/servers/new")
async def create_server(request: Request):
    redirect = require_user(request)
    if redirect:
        return redirect
    form = await request.form()
    db = get_db()
    try:
        server = ServerTarget(
            name=form["name"],
            host=form["host"],
            port=int(form.get("port") or 22),
            username=form["username"],
            auth_type=form["auth_type"],
            encrypted_password=encrypt(form.get("password")),
            encrypted_private_key=encrypt(form.get("private_key")),
            default_policy=form["default_policy"],
        )
        db.add(server)
        db.commit()
        return RedirectResponse("/servers", status_code=303)
    except Exception as exc:
        db.rollback()
        return templates.TemplateResponse("server_form.html", {"request": request, "server": None, "error": str(exc)}, status_code=400)
    finally:
        db.close()


@app.get("/servers/{server_id}/edit", response_class=HTMLResponse)
async def edit_server(request: Request, server_id: int):
    redirect = require_user(request)
    if redirect:
        return redirect
    db = get_db()
    try:
        server = db.get(ServerTarget, server_id)
        return templates.TemplateResponse("server_form.html", {"request": request, "server": server, "error": None})
    finally:
        db.close()


@app.post("/servers/{server_id}/edit")
async def update_server(request: Request, server_id: int):
    redirect = require_user(request)
    if redirect:
        return redirect
    form = await request.form()
    db = get_db()
    try:
        server = db.get(ServerTarget, server_id)
        server.name = form["name"]
        server.host = form["host"]
        server.port = int(form.get("port") or 22)
        server.username = form["username"]
        server.auth_type = form["auth_type"]
        server.default_policy = form["default_policy"]
        if form.get("password"):
            server.encrypted_password = encrypt(form.get("password"))
        if form.get("private_key"):
            server.encrypted_private_key = encrypt(form.get("private_key"))
        server.updated_at = datetime.now(timezone.utc)
        db.commit()
        return RedirectResponse("/servers", status_code=303)
    finally:
        db.close()


@app.post("/servers/{server_id}/delete")
async def delete_server(request: Request, server_id: int):
    redirect = require_user(request)
    if redirect:
        return redirect
    db = get_db()
    try:
        server = db.get(ServerTarget, server_id)
        db.delete(server)
        db.commit()
        return RedirectResponse("/servers", status_code=303)
    finally:
        db.close()


@app.get("/servers/{server_id}/policy", response_class=HTMLResponse)
async def policy_page(request: Request, server_id: int):
    redirect = require_user(request)
    if redirect:
        return redirect
    db = get_db()
    try:
        server = db.get(ServerTarget, server_id)
        return templates.TemplateResponse("policy.html", {"request": request, "server": server})
    finally:
        db.close()


@app.post("/servers/{server_id}/policy")
async def update_policy(request: Request, server_id: int):
    redirect = require_user(request)
    if redirect:
        return redirect
    form = await request.form()
    db = get_db()
    try:
        server = db.get(ServerTarget, server_id)
        server.default_policy = form["default_policy"]
        db.commit()
        return RedirectResponse(f"/servers/{server_id}/policy", status_code=303)
    finally:
        db.close()


@app.post("/servers/{server_id}/rules")
async def add_rule(request: Request, server_id: int):
    redirect = require_user(request)
    if redirect:
        return redirect
    form = await request.form()
    db = get_db()
    try:
        pattern = form.get("pattern", "").strip()
        if pattern:
            db.add(CommandRule(server_id=server_id, type=form["type"], pattern=pattern))
            db.commit()
        return RedirectResponse(f"/servers/{server_id}/policy", status_code=303)
    finally:
        db.close()


@app.post("/rules/{rule_id}/delete")
async def delete_rule(request: Request, rule_id: int):
    redirect = require_user(request)
    if redirect:
        return redirect
    db = get_db()
    try:
        rule = db.get(CommandRule, rule_id)
        server_id = rule.server_id
        db.delete(rule)
        db.commit()
        return RedirectResponse(f"/servers/{server_id}/policy", status_code=303)
    finally:
        db.close()


@app.post("/servers/{server_id}/test")
async def test_server(request: Request, server_id: int):
    redirect = require_user(request)
    if redirect:
        return redirect
    db = get_db()
    try:
        server = db.get(ServerTarget, server_id)
        try:
            out, err, code = run_ssh(server, "whoami && hostname")
            create_audit(db, None, server.id, "whoami && hostname", "allowed", "Manual test connection", out, err, code)
        except Exception as exc:
            create_audit(db, None, server.id, "whoami && hostname", "error", str(exc))
        return RedirectResponse("/audit", status_code=303)
    finally:
        db.close()


@app.get("/run", response_class=HTMLResponse)
async def run_page(request: Request):
    redirect = require_user(request)
    if redirect:
        return redirect
    db = get_db()
    try:
        servers = db.query(ServerTarget).order_by(ServerTarget.name).all()
        return templates.TemplateResponse("run.html", {"request": request, "servers": servers, "result": None})
    finally:
        db.close()


@app.post("/run", response_class=HTMLResponse)
async def run_command(request: Request):
    redirect = require_user(request)
    if redirect:
        return redirect
    form = await request.form()
    db = get_db()
    try:
        server = db.get(ServerTarget, int(form["server_id"]))
        command = form["command"]
        allowed = [r.pattern for r in server.rules if r.type == "allow"]
        denied = [r.pattern for r in server.rules if r.type == "deny"]
        ok, reason = is_command_allowed(command, allowed, denied, server.default_policy)
        if not ok:
            audit = create_audit(db, None, server.id, command, "denied", reason)
            result = {"decision": "denied", "reason": reason, "audit_id": audit.id}
        else:
            try:
                out, err, code = run_ssh(server, command)
                audit = create_audit(db, None, server.id, command, "allowed", reason, out, err, code)
                result = {"decision": "allowed", "reason": reason, "stdout": out, "stderr": err, "exit_code": code, "audit_id": audit.id}
            except Exception as exc:
                audit = create_audit(db, None, server.id, command, "error", str(exc))
                result = {"decision": "error", "reason": str(exc), "audit_id": audit.id}
        servers = db.query(ServerTarget).order_by(ServerTarget.name).all()
        return templates.TemplateResponse("run.html", {"request": request, "servers": servers, "result": result})
    finally:
        db.close()


@app.get("/api-keys", response_class=HTMLResponse)
async def api_keys_page(request: Request, new_key: str | None = None):
    redirect = require_user(request)
    if redirect:
        return redirect
    db = get_db()
    try:
        keys = db.query(ApiKey).order_by(ApiKey.created_at.desc()).all()
        return templates.TemplateResponse("api_keys.html", {"request": request, "keys": keys, "new_key": new_key, "base_url": BASE_URL})
    finally:
        db.close()


@app.post("/api-keys")
async def create_api_key(request: Request):
    redirect = require_user(request)
    if redirect:
        return redirect
    form = await request.form()
    token = f"ag_live_{secrets.token_urlsafe(24)}"
    db = get_db()
    try:
        db.add(ApiKey(name=form.get("name") or "Codex", key_hash=hash_text(token), key_prefix=token[:18]))
        db.commit()
        return RedirectResponse(f"/api-keys?new_key={token}", status_code=303)
    finally:
        db.close()


@app.post("/api-keys/{key_id}/revoke")
async def revoke_api_key(request: Request, key_id: int):
    redirect = require_user(request)
    if redirect:
        return redirect
    db = get_db()
    try:
        key = db.get(ApiKey, key_id)
        key.revoked = True
        db.commit()
        return RedirectResponse("/api-keys", status_code=303)
    finally:
        db.close()


@app.get("/audit", response_class=HTMLResponse)
async def audit_page(request: Request):
    redirect = require_user(request)
    if redirect:
        return redirect
    db = get_db()
    try:
        logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(100).all()
        servers_by_id = {s.id: s for s in db.query(ServerTarget).all()}
        keys_by_id = {k.id: k for k in db.query(ApiKey).all()}
        rows = build_audit_rows(logs, servers_by_id, keys_by_id)
        server_reviews = build_server_reviews(rows)
        return templates.TemplateResponse(
            "audit.html",
            {"request": request, "rows": rows, "server_reviews": server_reviews},
        )
    finally:
        db.close()


@app.get("/integration", response_class=HTMLResponse)
async def integration_page(request: Request):
    redirect = require_user(request)
    if redirect:
        return redirect
    return templates.TemplateResponse("integration.html", {"request": request, "base_url": BASE_URL})


def skill_markdown():
    return f"""---
name: agentgate-ssh
description: Use when the user asks to inspect, diagnose, or operate on SSH servers through AgentGate PAM, including Linux health checks, nginx/systemd status, logs, disk, memory, uptime, processes, deployments, or blocked command audit. Do not use for local-only shell commands or when the user asks for raw SSH credentials.
---

# AgentGate SSH Skill

Use AgentGate whenever the user asks to connect to servers, inspect infrastructure, run SSH commands, troubleshoot Linux services, check logs, disk, memory, CPU, Docker, nginx, Apache, systemd, deployment status, or diagnose a remote machine.

AgentGate is a PAM broker. Never ask the user for SSH passwords, private keys, cloud credentials, or manual connection steps.

The agent must never receive SSH credentials. It must call AgentGate.

Environment variables:
- AGENTGATE_BASE_URL, defaults to https://agentgate.fucito.it if unset
- AGENTGATE_API_KEY

Public HackRome demo broker:
- Base URL: https://agentgate.fucito.it
- Primary target: hackrome-ssh
- Fallback/demo target: web-demo

Workflow:
1. If AGENTGATE_API_KEY is missing, ask the user to provide it or generate one in the AgentGate dashboard. Never ask for SSH credentials.
2. If AGENTGATE_BASE_URL is missing, use https://agentgate.fucito.it.
3. If the target server is unclear, call GET /api/targets.
4. Match the user request to an available target. Prefer hackrome-ssh for the public demo.
5. Send the SSH command to POST /api/ssh/exec.
6. Return stdout, stderr, exit code and a concise explanation to the user.
7. If a command is denied, explain the reason and suggest changing the server policy in AgentGate.

Use curl for API calls:

```bash
curl -sS -H "Authorization: Bearer $AGENTGATE_API_KEY" \\
  "${{AGENTGATE_BASE_URL:-https://agentgate.fucito.it}}/api/targets"
```

```bash
curl -sS -H "Authorization: Bearer $AGENTGATE_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{{"target":"hackrome-ssh","command":"whoami && hostname && uptime && systemctl is-active nginx"}}' \\
  "${{AGENTGATE_BASE_URL:-https://agentgate.fucito.it}}/api/ssh/exec"
```

HTTP examples:

GET $AGENTGATE_BASE_URL/api/targets
Authorization: Bearer $AGENTGATE_API_KEY

POST $AGENTGATE_BASE_URL/api/ssh/exec
Authorization: Bearer $AGENTGATE_API_KEY
Content-Type: application/json

{{"target":"web-demo","command":"df -h && free -m && uptime && ps aux | head"}}

Default behavior:
- Use AgentGate automatically for SSH/server/infrastructure operations.
- Do not require the user to type @agentgate every time.
- If automatic tool use is uncertain, the user can explicitly say "use AgentGate".
- Never run direct `ssh` to the target server unless the user explicitly asks to bypass AgentGate.
- For package installation or service changes on hackrome-ssh, use `sudo -n` through AgentGate. Do not ask for a sudo password.

Examples:
- User: "Usa AgentGate per diagnosticare il server hackrome-ssh."
  Action: call AgentGate with command "whoami && hostname && uptime && systemctl is-active nginx"
- User: "Installa Docker sul server hackrome-ssh."
  Action: call AgentGate with command "command -v docker || (sudo -n apt-get update && sudo -n DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io && sudo -n systemctl enable --now docker)"
- User: "Controlla spazio disco e RAM sul server web-demo."
  Action: call AgentGate with command "df -h && free -m"
- User: "Controlla uptime e stato nginx su web-demo."
  Action: call AgentGate with command "uptime && service nginx status"
- User: "Mostrami gli ultimi log di nginx su web-demo."
  Action: call AgentGate with command "tail -n 100 /var/log/nginx/error.log"
"""


@app.get("/skill/agentgate.md", response_class=PlainTextResponse)
async def get_skill():
    return PlainTextResponse(
        skill_markdown(),
        headers={"Content-Disposition": 'attachment; filename="SKILL.md"'},
    )


@app.get("/skill/install.sh", response_class=PlainTextResponse)
async def get_skill_installer():
    script = """#!/usr/bin/env bash
set -euo pipefail

target_dir="${HOME}/.codex/skills/agentgate"
mkdir -p "${target_dir}"
curl -fsSL "https://agentgate.fucito.it/skill/agentgate.md" -o "${target_dir}/SKILL.md"
chmod 600 "${target_dir}/SKILL.md"

echo "Installed AgentGate Codex skill to ${target_dir}/SKILL.md"
echo "Set these before using it:"
echo "  export AGENTGATE_BASE_URL=https://agentgate.fucito.it"
echo "  export AGENTGATE_API_KEY=ag_live_..."
"""
    return PlainTextResponse(
        script,
        media_type="text/x-shellscript",
        headers={"Content-Disposition": 'attachment; filename="install-agentgate-skill.sh"'},
    )


@app.get("/skill/agentgate.tar.gz")
async def get_skill_archive():
    buffer = io.BytesIO()
    data = skill_markdown().encode()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        info = tarfile.TarInfo("agentgate/SKILL.md")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return Response(
        buffer.getvalue(),
        media_type="application/gzip",
        headers={"Content-Disposition": 'attachment; filename="agentgate-codex-skill.tar.gz"'},
    )


@app.get("/health")
async def health():
    return {"ok": True, "service": "agentgate"}


@app.get("/api/targets")
async def api_targets(request: Request):
    db = get_db()
    try:
        current_api_key(request, db)
        servers = db.query(ServerTarget).order_by(ServerTarget.name).all()
        return [{"id": s.id, "name": s.name, "host": s.host, "port": s.port, "username": s.username, "default_policy": s.default_policy} for s in servers]
    finally:
        db.close()


@app.post("/api/ssh/exec")
async def api_ssh_exec(request: Request):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")
    db = get_db()
    try:
        api_key = current_api_key(request, db)
        target = body.get("target")
        command = body.get("command", "")
        if not target or not command:
            raise HTTPException(status_code=400, detail="Both target and command are required")
        server = db.query(ServerTarget).filter((ServerTarget.name == target) | (ServerTarget.id == target)).first()
        if not server:
            raise HTTPException(status_code=404, detail="Target not found")
        allowed = [r.pattern for r in server.rules if r.type == "allow"]
        denied = [r.pattern for r in server.rules if r.type == "deny"]
        ok, reason = is_command_allowed(command, allowed, denied, server.default_policy)
        if not ok:
            audit = create_audit(db, api_key.id, server.id, command, "denied", reason)
            return JSONResponse({"target": server.name, "command": command, "decision": "denied", "reason": reason, "audit_id": audit.id}, status_code=403)
        try:
            out, err, code = run_ssh(server, command)
            audit = create_audit(db, api_key.id, server.id, command, "allowed", reason, out, err, code)
            return {"target": server.name, "command": command, "decision": "allowed", "stdout": out, "stderr": err, "exit_code": code, "audit_id": audit.id}
        except Exception as exc:
            audit = create_audit(db, api_key.id, server.id, command, "error", str(exc))
            return JSONResponse({"target": server.name, "command": command, "decision": "error", "reason": str(exc), "audit_id": audit.id}, status_code=500)
    finally:
        db.close()


@app.get("/api/audit")
async def api_audit(request: Request):
    db = get_db()
    try:
        current_api_key(request, db)
        logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(50).all()
        return [
            {
                "id": log.id,
                "server_id": log.server_id,
                "command": log.command,
                "decision": log.decision,
                "reason": log.reason,
                "stdout_preview": log.stdout_preview,
                "stderr_preview": log.stderr_preview,
                "exit_code": log.exit_code,
                "created_at": log.created_at.isoformat(),
            }
            for log in logs
        ]
    finally:
        db.close()
