# Satellite Intelligence Platform

This repository currently delivers the **User / Analyst module** of the planned offline-first platform. Accounts, MFA, project access, AOIs, analysis ownership, reviews, approved exports, and audit records persist in PostGIS. Analysis results are still clearly labeled demo fixtures; Sentinel-2 ingestion and ML inference belong to later modules.

## Start the appliance

1. Copy `.env.example` to `.env`. Set `DB_PASSWORD` to a random hexadecimal value (for example, generate one with `openssl rand -hex 32`). Set `SITE_HOST` to the DNS name users will open, or leave `localhost` for one-machine testing.
2. Run `docker compose up -d --build`.
3. Bootstrap the first administrator:

   ```sh
   docker compose exec api python -m app.admin bootstrap --email admin@example.org --name Administrator
   ```

4. Open `https://localhost` (or `https://$SITE_HOST`). The gateway creates a local TLS certificate. Trust its local CA on client machines before production use. The CA certificate is in the `gateway` container at `/data/caddy/pki/authorities/local/root.crt`.
5. On the login page, open **Enroll an account**. Enter the one-time token from bootstrap, add the displayed TOTP URI to an authenticator, set a password of at least 12 characters, and submit the current code. Save the ten recovery codes once shown, then sign in.

The API and database are reachable only inside the Compose network. Browser requests reach the API through the same-origin `/api/v1` route. The `security-data` volume stores the encryption key for TOTP secrets; retain it with the database backup. Losing this key requires resetting every user's MFA enrollment.

## Analyst workflow

- Admins create projects and local accounts, assign analyst or viewer membership, manage account recovery, approve or deny each export request, and inspect audit history.
- Analysts draw AOIs on the coordinate grid or import one polygon from a GeoJSON/KML file. AOI revisions are preserved so analyses keep the exact submitted boundary. Analysts run analyses, confirm or reject results, add notes, and request GeoJSON/PDF/PNG exports.
- Viewers read project AOIs, analyses, results, and review history. They cannot modify them or request exports.
- Approved exports are immutable snapshots. Only the requesting analyst and admins can download them, for seven days after approval.

The grid is a boundary editor. Satellite basemaps and before/after imagery are part of the presentation and EO modules. PDF and PNG exports currently show vector evidence and review status from the selected analysis; they do not claim to contain real Sentinel-2 imagery.

## Security and operations

- Sessions are stored server-side and may be revoked. A session expires after 30 minutes without activity or 12 hours total. Changing membership or resetting an account revokes its active sessions.
- Each mutation requires a CSRF token. The gateway serves HTTPS, and browser cookies are Secure, HTTP-only, and SameSite Strict.
- The audit table is append-only in Postgres. Keep the database and the `security-data` volume in encrypted, access-controlled backups for at least seven years; periodically test a restore on a separate appliance. The application does not automatically delete audit records.
- API schemas are available inside the API container at `/docs`; operators may inspect them with `docker compose exec api` or an internal network client.

## Verify

```sh
cd backend
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m pytest -q
cd ../frontend
npm ci
npm run build
```

The backend tests use an isolated SQLite database; the appliance uses PostGIS. The initial Alembic migration runs automatically when the API container starts.
