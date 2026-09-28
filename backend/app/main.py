import io
import json
from datetime import date, timedelta
from typing import Literal
from uuid import uuid4

import pyotp
from fastapi import Depends, FastAPI, File, HTTPException, Response, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, EmailStr, Field
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from sqlalchemy import select, update
from sqlalchemy.orm import Session as DBSession

from .db import AOI, AOIRevision, Analysis, Audit, Export, Membership, Project, Result, ReviewEvent, Session, User, get_db, now
from .geometry import normalize_geometry, parse_import
from .schemas import AnalysisRequest, ChangeType
from .security import Actor, COOKIE_NAME, audit, current_actor, enroll, issue_enrollment, login, public_user, require_admin, revoke_user_sessions
from .secrets import decrypt_totp, encrypt_totp
from .services import demo_results

app = FastAPI(title="Satellite Intelligence Platform", version="0.2.0")


@app.middleware("http")
async def no_api_cache(request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/v1/"):
        response.headers["Cache-Control"] = "no-store"
    return response


class LoginInput(BaseModel):
    email: EmailStr
    password: str
    code: str


class EnrollmentInput(BaseModel):
    token: str
    password: str
    code: str


class PasswordInput(BaseModel):
    current_password: str
    code: str
    new_password: str = Field(min_length=12, max_length=128)


class UserInput(BaseModel):
    email: EmailStr
    name: str = Field(min_length=1, max_length=160)
    is_admin: bool = False


class ProjectInput(BaseModel):
    name: str = Field(min_length=1, max_length=160)


class MemberInput(BaseModel):
    user_id: str
    role: Literal["analyst", "viewer"]


class AOIInput(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    geometry: dict


class AOIUpdate(BaseModel):
    geometry: dict


class AnalysisInput(BaseModel):
    project_id: str
    aoi_revision_id: str
    start_date: date
    end_date: date
    change_types: list[ChangeType] = Field(default_factory=lambda: list(ChangeType))
    max_cloud_cover: int = Field(default=20, ge=0, le=100)


class ReviewInput(BaseModel):
    decision: Literal["confirmed", "rejected"]
    note: str | None = Field(default=None, max_length=2000)
    expected_version: int = Field(ge=0)


class ExportInput(BaseModel):
    analysis_id: str
    result_id: str | None = None
    format: Literal["geojson", "pdf", "png"]


class SearchInput(BaseModel):
    project_id: str
    query: str = Field(min_length=3, max_length=500)


def project_access(db: DBSession, actor: Actor, project_id: str, action: str = "view"):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404, "Project not found")
    if actor.user.is_admin:
        return project
    membership = db.scalar(select(Membership).where(Membership.user_id == actor.user.id, Membership.project_id == project_id))
    if not membership:
        raise HTTPException(404, "Project not found")
    if action != "view" and membership.role != "analyst":
        raise HTTPException(403, "Analyst role required")
    return project


def get_analysis(db: DBSession, actor: Actor, analysis_id: str, action: str = "view"):
    analysis = db.get(Analysis, analysis_id)
    if not analysis:
        raise HTTPException(404, "Analysis not found")
    project_access(db, actor, analysis.project_id, action)
    return analysis


def get_result(db: DBSession, actor: Actor, result_id: str, action: str = "view"):
    result = db.get(Result, result_id)
    if not result:
        raise HTTPException(404, "Result not found")
    analysis = get_analysis(db, actor, result.analysis_id, action)
    return result, analysis


def result_data(result: Result):
    return {**result.payload, "review_status": result.review_status, "reviewer_note": result.review_note,
            "review_version": result.review_version}


def aoi_data(db: DBSession, aoi: AOI):
    revision = db.scalar(select(AOIRevision).where(AOIRevision.aoi_id == aoi.id, AOIRevision.revision == aoi.current_revision))
    return {"id": aoi.id, "project_id": aoi.project_id, "name": aoi.name,
            "revision": aoi.current_revision, "revision_id": revision.id, "geometry": revision.geometry}


def export_data(item: Export):
    return {"id": item.id, "project_id": item.project_id, "analysis_id": item.analysis_id,
            "result_id": item.result_id, "requester_id": item.requester_id, "format": item.format,
            "status": item.status, "created_at": item.created_at, "decided_at": item.decided_at,
            "expires_at": item.expires_at, "result_count": len(item.snapshot.get("results", [])),
            "aoi_revision_id": item.snapshot.get("aoi_revision_id")}


@app.get("/health")
def health():
    return {"status": "ok", "mode": "offline-first"}


@app.post("/v1/auth/enrollment-info")
def enrollment_info(payload: dict, db: DBSession = Depends(get_db)):
    from .db import Enrollment
    from .security import digest, aware
    item = db.get(Enrollment, digest(payload.get("token", "")))
    if not item or item.used_at or aware(item.expires_at) < now():
        raise HTTPException(400, "Invalid or expired enrollment token")
    user = db.get(User, item.user_id)
    return {"email": user.email, "totp_uri": pyotp.TOTP(decrypt_totp(user.totp_secret)).provisioning_uri(name=user.email, issuer_name="Satellite Intelligence")}


@app.post("/v1/auth/enroll")
def enroll_account(payload: EnrollmentInput, db: DBSession = Depends(get_db)):
    return {"recovery_codes": enroll(db, payload.token, payload.password, payload.code)}


@app.post("/v1/auth/login")
def login_account(payload: LoginInput, response: Response, db: DBSession = Depends(get_db)):
    return login(db, payload.email, payload.password, payload.code, response)


@app.get("/v1/auth/session")
def auth_session(actor: Actor = Depends(current_actor)):
    return {"user": public_user(actor.user), "csrf_token": actor.session.csrf_token}


@app.post("/v1/auth/logout")
def logout(response: Response, actor: Actor = Depends(current_actor), db: DBSession = Depends(get_db)):
    actor.session.revoked_at = now()
    audit(db, actor.user.id, "auth.logout", actor.user.id)
    db.commit()
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"status": "logged_out"}


@app.post("/v1/auth/logout-all")
def logout_all(response: Response, actor: Actor = Depends(current_actor), db: DBSession = Depends(get_db)):
    revoke_user_sessions(db, actor.user.id)
    audit(db, actor.user.id, "auth.logout_all", actor.user.id)
    db.commit()
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"status": "logged_out"}


@app.get("/v1/me")
def me(actor: Actor = Depends(current_actor), db: DBSession = Depends(get_db)):
    memberships = db.scalars(select(Membership).where(Membership.user_id == actor.user.id)).all()
    return {**public_user(actor.user), "projects": [{"project_id": m.project_id, "role": m.role} for m in memberships]}


@app.get("/v1/me/sessions")
def list_sessions(actor: Actor = Depends(current_actor), db: DBSession = Depends(get_db)):
    from .security import aware
    sessions = db.scalars(select(Session).where(Session.user_id == actor.user.id, Session.revoked_at.is_(None))).all()
    return [{"id": s.token_hash, "created_at": s.created_at, "last_seen_at": s.last_seen_at,
             "current": s.token_hash == actor.session.token_hash} for s in sessions
            if aware(s.created_at) + timedelta(hours=12) >= now() and aware(s.last_seen_at) + timedelta(minutes=30) >= now()]


@app.delete("/v1/me/sessions/{session_id}")
def revoke_session(session_id: str, actor: Actor = Depends(current_actor), db: DBSession = Depends(get_db)):
    session = db.get(Session, session_id)
    if not session or session.user_id != actor.user.id:
        raise HTTPException(404, "Session not found")
    session.revoked_at = now()
    audit(db, actor.user.id, "auth.session_revoke", actor.user.id)
    db.commit()
    return {"status": "revoked"}


@app.post("/v1/me/password")
def change_password(payload: PasswordInput, response: Response, actor: Actor = Depends(current_actor), db: DBSession = Depends(get_db)):
    from argon2.exceptions import VerificationError
    from .security import hasher, verify_factor
    try:
        hasher.verify(actor.user.password_hash, payload.current_password)
    except VerificationError as exc:
        raise HTTPException(401, "Invalid credentials") from exc
    if not verify_factor(actor.user, payload.code):
        raise HTTPException(401, "Invalid credentials")
    actor.user.password_hash = hasher.hash(payload.new_password)
    revoke_user_sessions(db, actor.user.id)
    audit(db, actor.user.id, "account.password_change", actor.user.id)
    db.commit()
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"status": "password_changed_sign_in_again"}


@app.post("/v1/admin/users", status_code=201)
def create_user(payload: UserInput, actor: Actor = Depends(current_actor), db: DBSession = Depends(get_db)):
    require_admin(actor)
    email = payload.email.lower().strip()
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(409, "Email already exists")
    user = User(email=email, name=payload.name.strip(), is_admin=payload.is_admin, totp_secret=encrypt_totp(pyotp.random_base32()))
    db.add(user)
    db.flush()
    token = issue_enrollment(db, user)
    audit(db, actor.user.id, "user.create", user.id)
    db.commit()
    return {"user": public_user(user), "enrollment_token": token,
            "totp_uri": pyotp.TOTP(decrypt_totp(user.totp_secret)).provisioning_uri(name=email, issuer_name="Satellite Intelligence")}


@app.get("/v1/admin/users")
def list_users(actor: Actor = Depends(current_actor), db: DBSession = Depends(get_db)):
    require_admin(actor)
    return [public_user(u) for u in db.scalars(select(User).order_by(User.email))]


@app.post("/v1/admin/users/{user_id}/reset")
def reset_user(user_id: str, actor: Actor = Depends(current_actor), db: DBSession = Depends(get_db)):
    require_admin(actor)
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    user.active = False
    user.password_hash = None
    user.totp_secret = encrypt_totp(pyotp.random_base32())
    user.last_totp_step = -1
    revoke_user_sessions(db, user.id)
    token = issue_enrollment(db, user)
    audit(db, actor.user.id, "user.reset", user.id)
    db.commit()
    return {"enrollment_token": token, "totp_uri": pyotp.TOTP(decrypt_totp(user.totp_secret)).provisioning_uri(name=user.email, issuer_name="Satellite Intelligence")}


@app.post("/v1/admin/users/{user_id}/suspend")
def suspend_user(user_id: str, actor: Actor = Depends(current_actor), db: DBSession = Depends(get_db)):
    require_admin(actor)
    if user_id == actor.user.id:
        raise HTTPException(409, "Cannot suspend your own account")
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    user.active = False
    revoke_user_sessions(db, user.id)
    audit(db, actor.user.id, "user.suspend", user.id)
    db.commit()
    return public_user(user)


@app.post("/v1/admin/users/{user_id}/activate")
def activate_user(user_id: str, actor: Actor = Depends(current_actor), db: DBSession = Depends(get_db)):
    require_admin(actor)
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    if not user.password_hash or not user.totp_secret:
        raise HTTPException(409, "User must complete enrollment first")
    user.active = True
    audit(db, actor.user.id, "user.activate", user.id)
    db.commit()
    return public_user(user)


@app.post("/v1/projects", status_code=201)
def create_project(payload: ProjectInput, actor: Actor = Depends(current_actor), db: DBSession = Depends(get_db)):
    require_admin(actor)
    project = Project(name=payload.name.strip())
    db.add(project)
    db.flush()
    audit(db, actor.user.id, "project.create", project.id, project.id)
    db.commit()
    return {"id": project.id, "name": project.name}


@app.get("/v1/projects")
def list_projects(actor: Actor = Depends(current_actor), db: DBSession = Depends(get_db)):
    projects = db.scalars(select(Project).order_by(Project.name)).all() if actor.user.is_admin else db.scalars(
        select(Project).join(Membership).where(Membership.user_id == actor.user.id).order_by(Project.name)).all()
    return [{"id": p.id, "name": p.name} for p in projects]


@app.put("/v1/projects/{project_id}/members")
def set_member(project_id: str, payload: MemberInput, actor: Actor = Depends(current_actor), db: DBSession = Depends(get_db)):
    require_admin(actor)
    project_access(db, actor, project_id)
    if not db.get(User, payload.user_id):
        raise HTTPException(404, "User not found")
    membership = db.scalar(select(Membership).where(Membership.user_id == payload.user_id, Membership.project_id == project_id))
    if membership:
        membership.role = payload.role
    else:
        db.add(Membership(user_id=payload.user_id, project_id=project_id, role=payload.role))
    revoke_user_sessions(db, payload.user_id)
    audit(db, actor.user.id, "member.set", payload.user_id, project_id, details={"role": payload.role})
    db.commit()
    return {"user_id": payload.user_id, "project_id": project_id, "role": payload.role}


@app.get("/v1/projects/{project_id}/members")
def list_members(project_id: str, actor: Actor = Depends(current_actor), db: DBSession = Depends(get_db)):
    require_admin(actor)
    project_access(db, actor, project_id)
    return [{"user_id": m.user_id, "project_id": m.project_id, "role": m.role} for m in db.scalars(
        select(Membership).where(Membership.project_id == project_id))]


@app.delete("/v1/projects/{project_id}/members/{user_id}")
def remove_member(project_id: str, user_id: str, actor: Actor = Depends(current_actor), db: DBSession = Depends(get_db)):
    require_admin(actor)
    membership = db.scalar(select(Membership).where(Membership.user_id == user_id, Membership.project_id == project_id))
    if not membership:
        raise HTTPException(404, "Membership not found")
    db.delete(membership)
    revoke_user_sessions(db, user_id)
    audit(db, actor.user.id, "member.remove", user_id, project_id)
    db.commit()
    return {"status": "removed"}


@app.post("/v1/projects/{project_id}/aois", status_code=201)
def create_aoi(project_id: str, payload: AOIInput, actor: Actor = Depends(current_actor), db: DBSession = Depends(get_db)):
    project_access(db, actor, project_id, "edit")
    geometry = normalize_geometry(payload.geometry)
    aoi = AOI(project_id=project_id, name=payload.name.strip(), created_by=actor.user.id)
    db.add(aoi)
    db.flush()
    db.add(AOIRevision(aoi_id=aoi.id, revision=1, geometry=geometry, created_by=actor.user.id))
    audit(db, actor.user.id, "aoi.create", aoi.id, project_id)
    db.commit()
    return aoi_data(db, aoi)


@app.post("/v1/projects/{project_id}/aois/import", status_code=201)
async def import_aoi(project_id: str, file: UploadFile = File(...), actor: Actor = Depends(current_actor), db: DBSession = Depends(get_db)):
    project_access(db, actor, project_id, "edit")
    content = await file.read(5 * 1024 * 1024 + 1)
    geometry = parse_import(file.filename or "", content)
    return create_aoi(project_id, AOIInput(name=(file.filename or "Imported AOI")[:160], geometry=geometry), actor, db)


@app.get("/v1/projects/{project_id}/aois")
def list_aois(project_id: str, actor: Actor = Depends(current_actor), db: DBSession = Depends(get_db)):
    project_access(db, actor, project_id)
    return [aoi_data(db, a) for a in db.scalars(select(AOI).where(AOI.project_id == project_id, AOI.deleted_at.is_(None)).order_by(AOI.created_at.desc()))]


@app.put("/v1/projects/{project_id}/aois/{aoi_id}")
def revise_aoi(project_id: str, aoi_id: str, payload: AOIUpdate, actor: Actor = Depends(current_actor), db: DBSession = Depends(get_db)):
    project_access(db, actor, project_id, "edit")
    aoi = db.get(AOI, aoi_id)
    if not aoi or aoi.project_id != project_id or aoi.deleted_at:
        raise HTTPException(404, "AOI not found")
    geometry = normalize_geometry(payload.geometry)
    aoi.current_revision += 1
    db.add(AOIRevision(aoi_id=aoi.id, revision=aoi.current_revision, geometry=geometry, created_by=actor.user.id))
    audit(db, actor.user.id, "aoi.revise", aoi.id, project_id, details={"revision": aoi.current_revision})
    db.commit()
    return aoi_data(db, aoi)


@app.delete("/v1/projects/{project_id}/aois/{aoi_id}")
def delete_aoi(project_id: str, aoi_id: str, actor: Actor = Depends(current_actor), db: DBSession = Depends(get_db)):
    project_access(db, actor, project_id, "edit")
    aoi = db.get(AOI, aoi_id)
    if not aoi or aoi.project_id != project_id or aoi.deleted_at:
        raise HTTPException(404, "AOI not found")
    aoi.deleted_at = now()
    audit(db, actor.user.id, "aoi.delete", aoi.id, project_id)
    db.commit()
    return {"status": "deleted"}


@app.post("/v1/analyses", status_code=202)
def create_analysis(payload: AnalysisInput, actor: Actor = Depends(current_actor), db: DBSession = Depends(get_db)):
    project_access(db, actor, payload.project_id, "edit")
    if payload.start_date >= payload.end_date:
        raise HTTPException(422, "Start date must precede end date")
    revision = db.get(AOIRevision, payload.aoi_revision_id)
    aoi = db.get(AOI, revision.aoi_id) if revision else None
    if not aoi or aoi.project_id != payload.project_id or aoi.deleted_at:
        raise HTTPException(404, "AOI revision not found")
    analysis = Analysis(project_id=payload.project_id, aoi_revision_id=revision.id, created_by=actor.user.id,
                        start_date=payload.start_date.isoformat(), end_date=payload.end_date.isoformat(),
                        change_types=[x.value for x in payload.change_types], max_cloud_cover=payload.max_cloud_cover,
                        job_id=str(uuid4()), state="completed", progress=100, detail="Demo fixture analysis complete")
    db.add(analysis)
    db.flush()
    request = AnalysisRequest(aoi=revision.geometry, start_date=payload.start_date, end_date=payload.end_date,
                              change_types=payload.change_types, max_cloud_cover=payload.max_cloud_cover)
    for item in demo_results(analysis.id, request):
        db.add(Result(id=str(item.id), analysis_id=analysis.id, payload=item.model_dump(mode="json")))
    audit(db, actor.user.id, "analysis.create", analysis.id, payload.project_id)
    db.commit()
    return {"id": analysis.job_id, "analysis_id": analysis.id, "project_id": analysis.project_id,
            "state": analysis.state, "progress": analysis.progress, "detail": analysis.detail}


@app.get("/v1/analyses")
def list_analyses(project_id: str, actor: Actor = Depends(current_actor), db: DBSession = Depends(get_db)):
    project_access(db, actor, project_id)
    return [{"id": a.id, "job_id": a.job_id, "state": a.state, "start_date": a.start_date,
             "end_date": a.end_date, "created_at": a.created_at} for a in db.scalars(
                 select(Analysis).where(Analysis.project_id == project_id).order_by(Analysis.created_at.desc()))]


@app.get("/v1/jobs/{job_id}")
def get_job(job_id: str, actor: Actor = Depends(current_actor), db: DBSession = Depends(get_db)):
    analysis = db.scalar(select(Analysis).where(Analysis.job_id == job_id))
    if not analysis:
        raise HTTPException(404, "Job not found")
    project_access(db, actor, analysis.project_id)
    return {"id": job_id, "analysis_id": analysis.id, "project_id": analysis.project_id,
            "state": analysis.state, "progress": analysis.progress, "detail": analysis.detail}


@app.get("/v1/results")
def list_results(project_id: str, analysis_id: str | None = None, actor: Actor = Depends(current_actor), db: DBSession = Depends(get_db)):
    project_access(db, actor, project_id)
    if analysis_id and get_analysis(db, actor, analysis_id).project_id != project_id:
        raise HTTPException(404, "Analysis not found")
    query = select(Result).join(Analysis).where(Analysis.project_id == project_id)
    if analysis_id:
        query = query.where(Result.analysis_id == analysis_id)
    return sorted((result_data(x) for x in db.scalars(query)), key=lambda x: x["confidence"], reverse=True)


@app.get("/v1/results/{result_id}")
def result_detail(result_id: str, actor: Actor = Depends(current_actor), db: DBSession = Depends(get_db)):
    result, _ = get_result(db, actor, result_id)
    return result_data(result)


@app.get("/v1/results/{result_id}/reviews")
def review_history(result_id: str, actor: Actor = Depends(current_actor), db: DBSession = Depends(get_db)):
    get_result(db, actor, result_id)
    return [{"id": x.id, "actor_id": x.actor_id, "decision": x.decision, "note": x.note, "created_at": x.created_at}
            for x in db.scalars(select(ReviewEvent).where(ReviewEvent.result_id == result_id).order_by(ReviewEvent.created_at))]


@app.post("/v1/results/{result_id}/review")
def review_result(result_id: str, payload: ReviewInput, actor: Actor = Depends(current_actor), db: DBSession = Depends(get_db)):
    result, analysis = get_result(db, actor, result_id, "edit")
    changed = db.execute(update(Result).where(Result.id == result.id, Result.review_version == payload.expected_version)
                         .values(review_status=payload.decision, review_note=payload.note,
                                 review_version=Result.review_version + 1, updated_at=now()))
    if changed.rowcount != 1:
        db.rollback()
        raise HTTPException(409, "Result was reviewed by someone else; refresh and try again")
    db.add(ReviewEvent(result_id=result.id, actor_id=actor.user.id, decision=payload.decision, note=payload.note))
    audit(db, actor.user.id, "result.review", result.id, analysis.project_id, details={"decision": payload.decision})
    db.commit()
    db.refresh(result)
    return result_data(result)


@app.post("/v1/search")
def search(payload: SearchInput, actor: Actor = Depends(current_actor), db: DBSession = Depends(get_db)):
    terms = set(payload.query.lower().replace("-", " ").split())
    results = list_results(payload.project_id, None, actor, db)
    return [r for r in results if terms & set(r["change_type"].replace("_", " ").split())]


def build_artifact(snapshot: dict, format: str) -> bytes:
    results = snapshot["results"]
    if format == "geojson":
        return json.dumps({"type": "FeatureCollection", "features": [
            {"type": "Feature", "geometry": r["geometry"], "properties": {k: v for k, v in r.items() if k != "geometry"}}
            for r in results]}, indent=2).encode()
    if format == "pdf":
        output = io.BytesIO()
        doc = canvas.Canvas(output, pagesize=A4)
        doc.setTitle("Satellite change analysis export")
        for page_start in range(0, max(len(results), 1), 18):
            doc.drawString(50, 790, "Satellite change analysis")
            doc.drawString(50, 765, f"Analysis: {snapshot['analysis_id']}")
            doc.drawString(50, 748, f"AOI revision: {snapshot['aoi_revision_id']}")
            for index, r in enumerate(results[page_start:page_start + 18]):
                y = 720 - index * 36
                doc.drawString(50, y, f"{r['change_type']} | confidence {r['confidence']:.2f} | {r['review_status']}")
                doc.drawString(60, y - 14, f"Earliest evidence: {r['earliest_supported_observation']}")
            doc.showPage()
        doc.save()
        return output.getvalue()
    from PIL import Image, ImageDraw
    image = Image.new("RGB", (1200, 630), "white")
    draw = ImageDraw.Draw(image)
    draw.text((50, 45), "Satellite change analysis", fill="black")
    geometries = [r["geometry"] for r in results]
    rings = [g["coordinates"][0] for g in geometries if g.get("type") == "Polygon"]
    aoi = snapshot.get("aoi_geometry", {})
    if aoi.get("type") == "Polygon":
        rings.insert(0, aoi["coordinates"][0])
    if rings:
        lon = [p[0] for ring in rings for p in ring]
        lat = [p[1] for ring in rings for p in ring]
        min_lon, max_lon, min_lat, max_lat = min(lon), max(lon), min(lat), max(lat)
        width = max(max_lon - min_lon, 0.001)
        height = max(max_lat - min_lat, 0.001)
        draw.rectangle((50, 90, 790, 575), fill="#e8f3ef", outline="#90b4a8", width=2)
        for index, ring in enumerate(rings):
            pixels = [(80 + (p[0] - min_lon) / width * 680, 545 - (p[1] - min_lat) / height * 425) for p in ring]
            draw.polygon(pixels, outline="#1769d7" if index == 0 else "#d34738", width=4)
    for index, r in enumerate(results[:10]):
        draw.text((820, 100 + index * 42), f"{r['change_type']}  {r['confidence']:.2f}", fill="black")
        draw.text((820, 116 + index * 42), r["review_status"], fill="#506779")
    output = io.BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


@app.post("/v1/exports", status_code=201)
def request_export(payload: ExportInput, actor: Actor = Depends(current_actor), db: DBSession = Depends(get_db)):
    analysis = get_analysis(db, actor, payload.analysis_id, "edit")
    if payload.result_id:
        result, _ = get_result(db, actor, payload.result_id)
        if result.analysis_id != analysis.id:
            raise HTTPException(404, "Result not in analysis")
        results = [result_data(result)]
    else:
        results = [result_data(x) for x in db.scalars(select(Result).where(Result.analysis_id == analysis.id))]
    item = Export(project_id=analysis.project_id, analysis_id=analysis.id, result_id=payload.result_id,
                  requester_id=actor.user.id, format=payload.format,
                  snapshot={"analysis_id": analysis.id, "aoi_revision_id": analysis.aoi_revision_id,
                            "aoi_geometry": db.get(AOIRevision, analysis.aoi_revision_id).geometry, "results": results})
    db.add(item)
    db.flush()
    audit(db, actor.user.id, "export.request", item.id, analysis.project_id, details={"format": payload.format})
    db.commit()
    return export_data(item)


@app.get("/v1/exports")
def list_exports(project_id: str, actor: Actor = Depends(current_actor), db: DBSession = Depends(get_db)):
    project_access(db, actor, project_id)
    query = select(Export).where(Export.project_id == project_id).order_by(Export.created_at.desc())
    if not actor.user.is_admin:
        query = query.where(Export.requester_id == actor.user.id)
    return [export_data(x) for x in db.scalars(query)]


@app.post("/v1/exports/{export_id}/decision")
def decide_export(export_id: str, decision: Literal["approved", "denied"], actor: Actor = Depends(current_actor), db: DBSession = Depends(get_db)):
    require_admin(actor)
    item = db.get(Export, export_id)
    if not item:
        raise HTTPException(404, "Export not found")
    if item.status != "pending":
        raise HTTPException(409, "Export already decided")
    item.approver_id = actor.user.id
    item.decided_at = now()
    if decision == "approved":
        try:
            item.artifact = build_artifact(item.snapshot, item.format)
            item.status = "approved"
            item.expires_at = now() + timedelta(days=7)
        except Exception:
            item.status = "failed"
    else:
        item.status = "denied"
    audit(db, actor.user.id, "export.decide", item.id, item.project_id, details={"status": item.status})
    db.commit()
    return export_data(item)


@app.get("/v1/exports/{export_id}/download")
def download_export(export_id: str, actor: Actor = Depends(current_actor), db: DBSession = Depends(get_db)):
    from .security import aware
    item = db.get(Export, export_id)
    if not item or (not actor.user.is_admin and item.requester_id != actor.user.id):
        raise HTTPException(404, "Export not found")
    project_access(db, actor, item.project_id)
    if item.status != "approved" or not item.expires_at or aware(item.expires_at) < now():
        raise HTTPException(410, "Export unavailable or expired")
    audit(db, actor.user.id, "export.download", item.id, item.project_id)
    db.commit()
    media = {"geojson": "application/geo+json", "pdf": "application/pdf", "png": "image/png"}[item.format]
    return StreamingResponse(io.BytesIO(item.artifact), media_type=media,
                             headers={"Content-Disposition": f'attachment; filename="export-{item.id}.{item.format}"'})


@app.get("/v1/admin/audit")
def audit_events(actor: Actor = Depends(current_actor), db: DBSession = Depends(get_db), project_id: str | None = None,
                 actor_id: str | None = None, action: str | None = None, since: date | None = None,
                 before: date | None = None, offset: int = 0, limit: int = 100):
    require_admin(actor)
    query = select(Audit)
    if project_id:
        query = query.where(Audit.project_id == project_id)
    if actor_id:
        query = query.where(Audit.actor_id == actor_id)
    if action:
        query = query.where(Audit.action == action)
    if since:
        query = query.where(Audit.created_at >= since)
    if before:
        query = query.where(Audit.created_at < before + timedelta(days=1))
    query = query.order_by(Audit.created_at.desc()).offset(max(offset, 0)).limit(min(max(limit, 1), 500))
    return [{"id": x.id, "actor_id": x.actor_id, "project_id": x.project_id, "action": x.action,
             "target_id": x.target_id, "outcome": x.outcome, "details": x.details, "created_at": x.created_at}
            for x in db.scalars(query)]


@app.post("/v1/sync/sentinel-2", status_code=202)
def sync_sentinel_2(actor: Actor = Depends(current_actor)):
    require_admin(actor)
    return {"status": "unavailable", "detail": "Sentinel-2 sync belongs to the EO pipeline module."}
