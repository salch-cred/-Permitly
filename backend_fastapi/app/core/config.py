from functools import lru_cache

from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    database_url: str = Field(alias="DATABASE_URL")
    session_secret: str = Field(alias="SESSION_SECRET")
    receipt_signing_secret: str = Field(alias="RECEIPT_SIGNING_SECRET")
    vault_master_secret: str = Field(alias="VAULT_MASTER_SECRET")

    cors_origins: str = Field(default="", alias="CORS_ORIGINS")  # comma-separated

    stripe_secret_key: str | None = Field(default=None, alias="STRIPE_SECRET_KEY")
    stripe_webhook_secret: str | None = Field(default=None, alias="STRIPE_WEBHOOK_SECRET")

    environment: str = Field(default="production", alias="ENVIRONMENT")

    model_config = {"extra": "ignore"}


@lru_cache
def get_settings() -> Settings:
    return Settings()
