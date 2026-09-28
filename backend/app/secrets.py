import os
from pathlib import Path

from cryptography.fernet import Fernet


def cipher():
    configured = os.getenv("MFA_ENCRYPTION_KEY")
    if configured:
        return Fernet(configured.encode())
    path = Path(os.getenv("MFA_KEY_PATH", "/tmp/satellite-mfa.key"))
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as file:
            file.write(Fernet.generate_key())
    except FileExistsError:
        pass
    return Fernet(path.read_bytes())


def encrypt_totp(secret: str) -> str:
    return cipher().encrypt(secret.encode()).decode()


def decrypt_totp(value: str) -> str:
    return cipher().decrypt(value.encode()).decode()
