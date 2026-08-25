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

# Setup SlowAPI Limiter for rate limiting
limiter = Limiter(key_func=get_remote_address, default_limits=[settings.RATE_LIMIT_STRING])

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="ScamCheck - Multi-layered Job Scam & Fraud Detection Web Application",
    version="1.0.0"
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Create static directory if missing
os.makedirs("app/static", exist_ok=True)
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Include Routers
app.include_router(api.router)
app.include_router(views.router)

@app.on_event("startup")
def on_startup():
    """Create database tables and seed initial data on application startup."""
    Base.metadata.create_all(bind=engine)
    seed_database()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
