import os
from datetime import datetime, timedelta, timezone
from uuid import UUID

import jwt

ALGORITHM = "HS256"
ACCESS_TOKEN_MINUTES = 30


def get_signing_key() -> str:
    key = os.environ["JWT_SECRET_KEY"]
    if len(key) < 32:
        raise RuntimeError("JWT_SECRET_KEY must contain at least 32 characters")
    return key


def create_access_token(user_id: UUID) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {
            "sub": str(user_id),
            "iat": now,
            "exp": now + timedelta(minutes=ACCESS_TOKEN_MINUTES),
        },
        get_signing_key(),
        algorithm=ALGORITHM,
    )


def decode_access_token(token: str) -> dict:
    return jwt.decode(
        token,
        get_signing_key(),
        algorithms=[ALGORITHM],
        options={"require": ["sub", "iat", "exp"]},
    )