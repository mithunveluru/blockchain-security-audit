import os
import sys
import secrets
import warnings


def _get_secret_key() -> str:
    key = os.environ.get("SECRET_KEY", "").strip()
    if key:
        return key
    if os.environ.get("FLASK_ENV") == "production" or os.environ.get("ENV") == "production":
        print(
            "[FATAL] SECRET_KEY env var is required in production. Aborting.",
            file=sys.stderr,
        )
        sys.exit(1)
    generated = secrets.token_hex(32)
    warnings.warn(
        f"SECRET_KEY not set. Generated a random key for this session: {generated[:8]}..."
        " Set SECRET_KEY env var to a fixed value for persistent sessions.",
        stacklevel=2,
    )
    return generated


class Config:
    SECRET_KEY: str = _get_secret_key()
    CORS_ORIGINS: str = os.environ.get("CORS_ORIGINS", "*")
    HOST: str = os.environ.get("HOST", "0.0.0.0")
    PORT: int = int(os.environ.get("PORT", "5000"))
    DEBUG: bool = os.environ.get("FLASK_DEBUG", "").lower() in ("1", "true")

    CHAIN_FILE: str = os.environ.get("CHAIN_FILE", "network_blockchain.json")
    INTEGRITY_CHECK_INTERVAL: int = int(os.environ.get("INTEGRITY_CHECK_INTERVAL", "30"))

    NETWORK_INTERFACE: str = os.environ.get("NETWORK_INTERFACE", "wlp0s20f3")
    # Missing Scapy is a fatal error unless this is set.
    ENABLE_SIMULATION_MODE: bool = os.environ.get("ENABLE_SIMULATION_MODE", "").lower() in ("1", "true")

    ML_LEARNING_WINDOW_DAYS: int = int(os.environ.get("ML_LEARNING_WINDOW_DAYS", "7"))

    @classmethod
    def validate(cls) -> list[str]:
        warnings_list = []
        if cls.CORS_ORIGINS == "*":
            warnings_list.append("CORS_ORIGINS=* allows all origins. Set CORS_ORIGINS in production.")
        return warnings_list


config = Config()
