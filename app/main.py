import os
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from app.config import settings
from app.database import engine, Base
from app.routers import api, views
from seed_data import seed_database

limiter = Limiter(key_func=get_remote_address, default_limits=[settings.RATE_LIMIT_STRING])

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="ScamCheck - Multi-layered Job Scam & Ghost Listing Detection Web Application",
    version="1.0.0"
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Absolute path resolution for Vercel Serverless environment
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
static_dir = os.path.join(BASE_DIR, "app", "static")
if not os.path.exists(static_dir):
    try:
        os.makedirs(static_dir, exist_ok=True)
    except Exception:
        pass

if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

# Include Routers
app.include_router(api.router)
app.include_router(views.router)

@app.on_event("startup")
def on_startup():
    """Create database tables and seed initial data on application startup."""
    try:
        Base.metadata.create_all(bind=engine)
        seed_database()
    except Exception as e:
        print(f"Startup initialization note: {e}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
