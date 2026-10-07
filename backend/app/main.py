from contextlib import asynccontextmanager
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .database import Base, engine, get_db
from .models import Scan, Target
from .schemas import ScanCreate, ScanRead, TargetCreate, TargetRead


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield
    engine.dispose()


app = FastAPI(title="Sentinel AI", lifespan=lifespan)


@app.get("/health")
def health():
    return {"status": "ok", "service": "sentinel-api"}


@app.post(
    "/targets",
    response_model=TargetRead,
    status_code=status.HTTP_201_CREATED,
)
def create_target(payload: TargetCreate, db: Session = Depends(get_db)):
    target = Target(
        name=payload.name,
        endpoint=str(payload.endpoint),
    )
    db.add(target)
    db.commit()
    db.refresh(target)
    return target


@app.get("/targets", response_model=list[TargetRead])
def list_targets(db: Session = Depends(get_db)):
    return db.scalars(
        select(Target).order_by(Target.created_at, Target.id)
    ).all()


@app.post(
    "/scans",
    response_model=ScanRead,
    status_code=status.HTTP_201_CREATED,
)
def create_scan(payload: ScanCreate, db: Session = Depends(get_db)):
    if db.get(Target, payload.target_id) is None:
        raise HTTPException(status_code=404, detail="Target not found")

    scan = Scan(target_id=payload.target_id)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


@app.get("/scans/{id}", response_model=ScanRead)
def get_scan(id: UUID, db: Session = Depends(get_db)):
    scan = db.get(Scan, id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan