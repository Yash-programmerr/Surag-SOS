import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, User, get_db
from app.main import app, build_artifact
from app.geometry import parse_import
from app.security import hasher
from app.secrets import encrypt_totp

AOI = {"type": "Polygon", "coordinates": [[[77.5, 24.7], [77.6, 24.7], [77.6, 24.8], [77.5, 24.7]]]}


@pytest.fixture
def world():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)

    def override():
        with factory() as db:
            yield db

    app.dependency_overrides[get_db] = override
    users = {}
    with factory() as db:
        for name, admin in [("admin", True), ("analyst", False), ("viewer", False), ("outsider", False)]:
            secret = pyotp.random_base32()
            user = User(email=f"{name}@example.org", name=name, is_admin=admin, active=True,
                        password_hash=hasher.hash("a-long-test-password"), totp_secret=encrypt_totp(secret))
            db.add(user)
            db.flush()
            users[name] = (user.id, secret)
        db.commit()

    clients = {}
    for name, (_, secret) in users.items():
        client = TestClient(app)
        login = client.post("/v1/auth/login", json={"email": f"{name}@example.org", "password": "a-long-test-password", "code": pyotp.TOTP(secret).now()})
        assert login.status_code == 200, login.text
        clients[name] = (client, {"X-CSRF-Token": login.json()["csrf_token"]})
    yield factory, users, clients
    app.dependency_overrides.clear()


def setup_project(world):
    _, users, clients = world
    admin, ah = clients["admin"]
    project = admin.post("/v1/projects", json={"name": "River survey"}, headers=ah).json()
    for name, role in [("analyst", "analyst"), ("viewer", "viewer")]:
        response = admin.put(f"/v1/projects/{project['id']}/members", json={"user_id": users[name][0], "role": role}, headers=ah)
        assert response.status_code == 200
    # Membership changes revoke sessions. Re-login with the next TOTP time step via recovery code.
    for name in ["analyst", "viewer"]:
        client, _ = clients[name]
        with world[0]() as db:
            user = db.get(User, users[name][0])
            from app.security import digest
            user.recovery_hashes = [digest("test-recovery-code")]
            db.commit()
        response = client.post("/v1/auth/login", json={"email": f"{name}@example.org", "password": "a-long-test-password", "code": "recovery:test-recovery-code"})
        assert response.status_code == 200
        clients[name] = (client, {"X-CSRF-Token": response.json()["csrf_token"]})
    return project


def test_project_aoi_review_export_and_audit(world):
    _, users, clients = world
    project = setup_project(world)
    analyst, headers = clients["analyst"]
    admin, admin_headers = clients["admin"]
    viewer, viewer_headers = clients["viewer"]
    outsider, _ = clients["outsider"]
    project_id = project["id"]

    assert outsider.get(f"/v1/projects/{project_id}/aois").status_code == 404
    assert viewer.post(f"/v1/projects/{project_id}/aois", json={"name": "River", "geometry": AOI}, headers=viewer_headers).status_code == 403
    aoi_response = analyst.post(f"/v1/projects/{project_id}/aois", json={"name": "River", "geometry": AOI}, headers=headers)
    assert aoi_response.status_code == 201, aoi_response.text
    aoi = aoi_response.json()
    assert analyst.post(f"/v1/projects/{project_id}/aois", json={"name": "Invalid", "geometry": {"type": "Point", "coordinates": [0, 0]}}, headers=headers).status_code == 422
    assert analyst.post(f"/v1/projects/{project_id}/aois", json={"name": "CSRF", "geometry": AOI}).status_code == 403

    job = analyst.post("/v1/analyses", json={"project_id": project_id, "aoi_revision_id": aoi["revision_id"],
                "start_date": "2026-03-01", "end_date": "2026-08-30"}, headers=headers)
    assert job.status_code == 202, job.text
    job = job.json()
    assert outsider.get(f"/v1/jobs/{job['id']}").status_code == 404
    results = analyst.get(f"/v1/results?project_id={project_id}&analysis_id={job['analysis_id']}").json()
    assert len(results) == 2
    result_id = results[0]["id"]
    assert viewer.post(f"/v1/results/{result_id}/review", json={"decision": "confirmed", "expected_version": 0}, headers=viewer_headers).status_code == 403
    reviewed = analyst.post(f"/v1/results/{result_id}/review", json={"decision": "confirmed", "note": "Checked", "expected_version": 0}, headers=headers)
    assert reviewed.status_code == 200
    assert analyst.post(f"/v1/results/{result_id}/review", json={"decision": "rejected", "expected_version": 0}, headers=headers).status_code == 409
    assert analyst.get(f"/v1/results/{result_id}/reviews").json()[0]["decision"] == "confirmed"

    export = analyst.post("/v1/exports", json={"analysis_id": job["analysis_id"], "result_id": result_id, "format": "geojson"}, headers=headers).json()
    assert analyst.get(f"/v1/exports/{export['id']}/download").status_code == 410
    assert viewer.get(f"/v1/exports/{export['id']}/download").status_code == 404
    decided = admin.post(f"/v1/exports/{export['id']}/decision?decision=approved", headers=admin_headers)
    assert decided.json()["status"] == "approved"
    downloaded = analyst.get(f"/v1/exports/{export['id']}/download")
    assert downloaded.status_code == 200
    assert downloaded.json()["features"][0]["properties"]["review_status"] == "confirmed"
    assert any(event["action"] == "export.download" for event in admin.get("/v1/admin/audit").json())
    assert outsider.get(f"/v1/results/{result_id}").status_code == 404


def test_membership_removal_revokes_access(world):
    _, users, clients = world
    project = setup_project(world)
    admin, admin_headers = clients["admin"]
    analyst, _ = clients["analyst"]
    removed = admin.delete(f"/v1/projects/{project['id']}/members/{users['analyst'][0]}", headers=admin_headers)
    assert removed.status_code == 200
    assert analyst.get(f"/v1/projects/{project['id']}/aois").status_code == 401


def test_export_formats_are_real_files():
    snapshot = {"analysis_id": "test-analysis", "aoi_revision_id": "test-aoi", "aoi_geometry": AOI,
                "results": [{"id": "test-result", "change_type": "construction", "confidence": 0.9,
                             "review_status": "confirmed", "earliest_supported_observation": "2026-08-22",
                             "geometry": AOI}]}
    assert build_artifact(snapshot, "geojson").startswith(b'{\n  "type": "FeatureCollection"')
    assert build_artifact(snapshot, "pdf").startswith(b"%PDF")
    assert build_artifact(snapshot, "png").startswith(b"\x89PNG")


def test_kml_import_is_normalized():
    kml = b'<kml xmlns="http://www.opengis.net/kml/2.2"><Placemark><Polygon><outerBoundaryIs><LinearRing><coordinates>77.5,24.7 77.6,24.7 77.6,24.8 77.5,24.7</coordinates></LinearRing></outerBoundaryIs></Polygon></Placemark></kml>'
    geometry = parse_import("boundary.kml", kml)
    assert geometry["type"] == "Polygon"
    assert geometry["coordinates"][0][0] == (77.5, 24.7)
