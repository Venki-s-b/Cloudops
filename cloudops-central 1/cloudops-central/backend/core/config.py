"""
Core configuration — all secrets from environment variables only.
Never hardcode credentials. Use a .env file locally, AWS Secrets Manager in prod.
"""
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # JWT
    secret_key: str = ""
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 480

    # Database
    database_url: str = "sqlite:///./cloudops.db"

    # CORS — comma-separated list of allowed origins
    allowed_origins: str = "http://localhost:8001,http://127.0.0.1:8001,http://localhost:3000"

    # Cache TTL (seconds)
    cache_ttl: int = 90

    # Default user credentials (override via env — never hardcode in production)
    admin_email: str = "admin@company.com"
    admin_password: str = ""
    viewer_email: str = "viewer@company.com"
    viewer_password: str = ""

    @property
    def origins_list(self) -> list[str]:
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]

    def validate_secret_key(self) -> None:
        _bad = {"", "CHANGE_ME_IN_PRODUCTION_use_secrets_manager", "your-secret-key-here-generate-with-python"}
        if not self.secret_key or self.secret_key in _bad:
            raise RuntimeError(
                "SECRET_KEY is not set or is still a placeholder.\n"
                "Generate one with:  python -c \"import secrets; print(secrets.token_hex(32))\""
            )
        if len(self.secret_key) < 32:
            raise RuntimeError("SECRET_KEY must be at least 32 characters long.")

    def validate_default_passwords(self) -> None:
        """Warn loudly if default seed passwords are missing."""
        if not self.admin_password or not self.viewer_password:
            raise RuntimeError(
                "ADMIN_PASSWORD and VIEWER_PASSWORD must be set in your .env file."
            )
        for label, pwd in [("ADMIN_PASSWORD", self.admin_password), ("VIEWER_PASSWORD", self.viewer_password)]:
            if len(pwd) < 12:
                raise RuntimeError(f"{label} must be at least 12 characters long.")


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    s.validate_secret_key()
    s.validate_default_passwords()
    return s
