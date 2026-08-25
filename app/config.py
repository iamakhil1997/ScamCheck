import os
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    PROJECT_NAME: str = "ScamCheck"
    DATABASE_URL: str = "sqlite:///./scamcheck.db"
    ANTHROPIC_API_KEY: str = ""
    ANTHROPIC_MODEL: str = "claude-sonnet-4-6"
    RATE_LIMIT_STRING: str = "20/minute"
    HASH_SALT: str = "scamcheck_secret_salt_2026"
    
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

settings = Settings()
