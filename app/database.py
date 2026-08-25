import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from app.config import settings

db_url = settings.DATABASE_URL

# Vercel serverless environment check: Use /tmp directory for SQLite on read-only serverless filesystems
if os.environ.get("VERCEL") or (db_url.startswith("sqlite:///") and db_url == "sqlite:///./scamcheck.db"):
    db_url = "sqlite:////tmp/scamcheck.db"

connect_args = {}
if db_url.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(
    db_url,
    connect_args=connect_args,
    echo=False
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
