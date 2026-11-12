from contextlib import asynccontextmanager
from fastapi import FastAPI
from .logging_setup import configure_logging
from .database import engine
from .migrations import upgrade
from .routers import auth, health, scans, targets, attacks, results
from .error_handlers import register_error_handlers


configure_logging()
@asynccontextmanager
async def lifespan(app: FastAPI):
    upgrade(engine)
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
app.include_router(attacks.router)
app.include_router(results.router)
