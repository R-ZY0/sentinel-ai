from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordRequestForm

from ..dependencies import get_current_user
from ..tokens import create_access_token
from ..database import get_db
from ..models import User
from ..passwords import hash_password,verify_password
from ..schemas import UserCreate, UserRead,Token

router = APIRouter(prefix="/auth", tags=["Authentication"])
DUMMY_PASSWORD_HASH = hash_password("Timing-check-only-not-an-account")

@router.post(
    "/register",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
)
def register(payload: UserCreate, db: Session = Depends(get_db)):
    email = str(payload.email).lower()

    existing_user = db.scalar(
        select(User.id).where(User.email == email)
    )
    if existing_user is not None:
        raise HTTPException(
            status_code=409,
            detail="Email is already registered",
        )

    user = User(
        email=email,
        password_hash=hash_password(payload.password.get_secret_value()),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

@router.post("/login", response_model=Token)
def login(
    form: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    email = form.username.strip().lower()
    user = db.scalar(select(User).where(User.email == email))

    stored_hash = user.password_hash if user else DUMMY_PASSWORD_HASH
    password_valid = verify_password(form.password, stored_hash)

    if user is None or not password_valid or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return Token(access_token=create_access_token(user.id))

@router.get("/me", response_model=UserRead)
def get_me(current_user: User = Depends(get_current_user)):
    return current_user