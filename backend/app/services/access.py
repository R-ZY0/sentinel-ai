from fastapi import HTTPException
from sqlalchemy import or_


def visible_to(model, user):
    # Unowned Week 1/2 records remain a shared legacy workspace. New records
    # have owners; never guess which registered user owns historical data.
    return or_(model.owner_id == user.id, model.owner_id.is_(None))


def require_visible(record, user, label):
    if record is None or (record.owner_id is not None and record.owner_id != user.id):
        raise HTTPException(404, f"{label} not found")
    return record
