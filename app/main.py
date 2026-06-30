"""ReachCheck FastAPI entry point.

Run:
    python -m app.main
    # or
    uvicorn app.main:app --reload
"""

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app import __version__
from app.api.scans import router as scans_router
from app.config import settings
from app.db.session import init_db
from app.web.routes import router as web_router

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR.parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Prepare database tables on application startup."""
    await init_db()
    yield


app = FastAPI(title=settings.app_name, version=__version__, lifespan=lifespan)

STATIC_DIR.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

app.include_router(scans_router)
app.include_router(web_router)


@app.get("/healthz")
async def healthz():
    """Simple health check."""
    return {"status": "ok", "version": __version__}


def main() -> None:
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
    )


if __name__ == "__main__":
    main()
