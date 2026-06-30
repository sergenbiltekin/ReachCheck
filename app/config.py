"""Application settings. Loaded from environment variables (REACHCHECK_ prefix)."""

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="REACHCHECK_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "ReachCheck"
    debug: bool = False

    database_url: str = "sqlite+aiosqlite:///./reachcheck.db"

    host: str = "127.0.0.1"
    port: int = 8000


settings = Settings()
