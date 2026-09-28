import argparse

import pyotp
from sqlalchemy import select

from .db import Base, SessionLocal, User, engine
from .security import issue_enrollment
from .secrets import decrypt_totp, encrypt_totp


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["bootstrap"])
    parser.add_argument("--email", required=True)
    parser.add_argument("--name", required=True)
    args = parser.parse_args()
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        if db.scalar(select(User).where(User.is_admin.is_(True))):
            raise SystemExit("An admin already exists; use the admin API.")
        user = User(email=args.email.lower().strip(), name=args.name, is_admin=True, totp_secret=encrypt_totp(pyotp.random_base32()))
        db.add(user)
        db.flush()
        token = issue_enrollment(db, user)
        db.commit()
        print(f"Enrollment token (valid 24 hours): {token}")
        print(f"TOTP setup URI: {pyotp.TOTP(decrypt_totp(user.totp_secret)).provisioning_uri(name=user.email, issuer_name='Satellite Intelligence')}")


if __name__ == "__main__":
    main()
