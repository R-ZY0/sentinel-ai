from contextlib import asynccontextmanager
from fastapi import FastAPI
from .logging_setup import configure_logging
from .database import Base, engine
from .schema_migrations import ensure_attack_case_id_column
from .routers import auth, health, scans, targets
from .error_handlers import register_error_handlers


configure_logging()
@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    ensure_attack_case_id_column(engine)
    try:
        yield
    finally:
        engine.dispose()


app = FastAPI(title="Sentinel AI", lifespan=lifespan)
register_error_handlers(app)

app.include_router(health.router)
app.include_router(targets.router)
app.include_router(scans.router)
app.include_router(auth.router)