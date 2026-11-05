from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session
from ..database import get_db
from ..dependencies import get_current_user
from ..models import Attack
from ..services.attack_catalog import sync_catalog

router = APIRouter(prefix="/attacks", tags=["Attacks"], dependencies=[Depends(get_current_user)])


@router.get("")
def list_attacks(db: Session = Depends(get_db)):
    sync_catalog(db)
    db.commit()
    return [{"id": item.id, "name": item.name, "engine": item.engine,
             "category": item.category, "active": item.active}
            for item in db.scalars(select(Attack).order_by(Attack.engine, Attack.id)).all()]
