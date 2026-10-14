import os
import secrets
from dataclasses import dataclass, field

MIN_TOKEN_LEN = 16
LOOPBACK = {"127.0.0.1", "::1", "localhost"}


class ConfigError(Exception):
    pass


def _bool(v):
    return str(v or "").strip().lower() in ("1", "true", "yes", "on")


def _int(env, key, default, lo=None, hi=None):
    raw = env.get(key, "")
    if raw == "":
        return default
    try:
        val = int(raw)
    except ValueError:
        raise ConfigError(f"{key} must be an integer, got {raw!r}")
    if (lo is not None and val < lo) or (hi is not None and val > hi):
        raise ConfigError(f"{key} must be between {lo} and {hi}, got {val}")
    return val


def _float(env, key, default, lo=None, hi=None):
    raw = env.get(key, "")
    if raw == "":
        return default
    try:
        val = float(raw)
    except ValueError:
        raise ConfigError(f"{key} must be a number, got {raw!r}")
    if (lo is not None and val < lo) or (hi is not None and val > hi):
        raise ConfigError(f"{key} must be between {lo} and {hi}, got {val}")
    return val


@dataclass
class Settings:
    env: str = "development"
    host: str = "127.0.0.1"
    port: int = 5000
    debug: bool = False
    cors_origins: list = field(default_factory=list)

    chain_file: str = "network_blockchain.json"
    checkpoint_file: str = ""
    data_dir: str = "data"
    integrity_check_interval: int = 30

    network_interface: str = ""
    simulation: bool = False

    tokens: dict = field(default_factory=dict)
    generated_admin_token: str = ""

    max_request_bytes: int = 64 * 1024
    rate_limit_per_min: int = 600
    rate_limit_write_per_min: int = 60
    rate_limit_copilot_per_min: int = 20

    alert_retention: int = 5000
    packet_ring: int = 5000
    packet_queue: int = 10000
    telemetry_retention_s: int = 3600

    portscan_ports: int = 20
    portscan_window: int = 10
    dos_pps: int = 200
    dos_window: int = 5
    dos_min_sources: int = 20
    brute_attempts: int = 10
    brute_window: int = 60
    exfil_bytes: int = 10 * 1024 * 1024
    exfil_max_age_s: int = 120
    alert_dedup_s: int = 30
    ledger_max_alerts_per_min: int = 120

    ml_window_s: int = 10
    ml_min_train: int = 200
    ml_threshold: float = 0.65

    copilot_provider: str = "auto"
    copilot_model: str = "claude-sonnet-5-5"
    copilot_timeout_s: int = 20
    anthropic_api_key: str = field(default="", repr=False)

    @property
    def production(self):
        return self.env == "production"

    @property
    def auth_enabled(self):
        return bool(self.tokens)

    @classmethod
    def from_env(cls, env=None):
        env = os.environ if env is None else env
        s = cls()
        s.env = (env.get("BLOCKAUDIT_ENV") or env.get("FLASK_ENV") or "development").strip().lower()
        if s.env not in ("development", "production", "test"):
            raise ConfigError(f"BLOCKAUDIT_ENV must be development, production or test, got {s.env!r}")
        s.host = env.get("HOST", s.host).strip() or s.host
        s.port = _int(env, "PORT", s.port, 1, 65535)
        s.debug = _bool(env.get("FLASK_DEBUG"))
        s.cors_origins = [o.strip() for o in env.get("CORS_ORIGINS", "").split(",") if o.strip()]
        s.chain_file = env.get("CHAIN_FILE", s.chain_file)
        s.checkpoint_file = env.get("CHECKPOINT_FILE", "") or s.chain_file + ".checkpoint"
        s.data_dir = env.get("DATA_DIR", s.data_dir)
        s.integrity_check_interval = _int(env, "INTEGRITY_CHECK_INTERVAL", s.integrity_check_interval, 1, 86400)
        s.network_interface = env.get("NETWORK_INTERFACE", "").strip()
        s.simulation = _bool(env.get("ENABLE_SIMULATION_MODE"))

        for role, key in (("admin", "BLOCKAUDIT_ADMIN_TOKEN"), ("analyst", "BLOCKAUDIT_ANALYST_TOKEN"),
                          ("viewer", "BLOCKAUDIT_VIEWER_TOKEN")):
            tok = env.get(key, "").strip()
            if tok:
                if len(tok) < MIN_TOKEN_LEN:
                    raise ConfigError(f"{key} must be at least {MIN_TOKEN_LEN} characters")
                s.tokens[role] = tok

        s.max_request_bytes = _int(env, "MAX_REQUEST_BYTES", s.max_request_bytes, 1024, 10 * 1024 * 1024)
        s.rate_limit_per_min = _int(env, "RATE_LIMIT_PER_MIN", s.rate_limit_per_min, 1)
        s.rate_limit_write_per_min = _int(env, "RATE_LIMIT_WRITE_PER_MIN", s.rate_limit_write_per_min, 1)
        s.rate_limit_copilot_per_min = _int(env, "RATE_LIMIT_COPILOT_PER_MIN", s.rate_limit_copilot_per_min, 1)
        s.alert_retention = _int(env, "ALERT_RETENTION", s.alert_retention, 100, 1_000_000)
        s.packet_queue = _int(env, "PACKET_QUEUE", s.packet_queue, 100, 1_000_000)

        s.portscan_ports = _int(env, "PORTSCAN_PORTS", s.portscan_ports, 2)
        s.dos_pps = _int(env, "DOS_PPS", s.dos_pps, 1)
        s.dos_min_sources = _int(env, "DOS_MIN_SOURCES", s.dos_min_sources, 2)
        s.brute_attempts = _int(env, "BRUTE_ATTEMPTS", s.brute_attempts, 2)
        s.exfil_bytes = _int(env, "EXFIL_BYTES", s.exfil_bytes, 1024)
        s.alert_dedup_s = _int(env, "ALERT_DEDUP_SECONDS", s.alert_dedup_s, 0, 86400)
        s.ml_min_train = _int(env, "ML_MIN_TRAIN_SAMPLES", s.ml_min_train, 20)
        s.ml_threshold = _float(env, "ML_THRESHOLD", s.ml_threshold, 0.4, 0.95)

        s.copilot_provider = env.get("COPILOT_PROVIDER", s.copilot_provider).strip().lower()
        if s.copilot_provider not in ("auto", "none", "anthropic"):
            raise ConfigError("COPILOT_PROVIDER must be auto, none or anthropic")
        s.copilot_model = env.get("COPILOT_MODEL", s.copilot_model).strip()
        s.copilot_timeout_s = _int(env, "COPILOT_TIMEOUT_SECONDS", s.copilot_timeout_s, 2, 120)
        s.anthropic_api_key = env.get("ANTHROPIC_API_KEY", "").strip()

        s._finalize(env)
        return s

    def _finalize(self, env):
        if self.production:
            if "admin" not in self.tokens:
                raise ConfigError("BLOCKAUDIT_ADMIN_TOKEN is required when BLOCKAUDIT_ENV=production")
            if self.debug:
                raise ConfigError("FLASK_DEBUG must be off in production")
            if "*" in self.cors_origins:
                raise ConfigError("CORS_ORIGINS=* is not allowed in production")
        elif not self.tokens:
            if self.host not in LOOPBACK:
                raise ConfigError(
                    "no auth tokens configured: set BLOCKAUDIT_ADMIN_TOKEN, or bind HOST to 127.0.0.1 "
                    "to get a generated one-time development token")
            self.generated_admin_token = secrets.token_urlsafe(24)
            self.tokens["admin"] = self.generated_admin_token

    def warnings(self):
        out = []
        if "*" in self.cors_origins:
            out.append("CORS_ORIGINS=* allows every origin to open the socket; list trusted origins instead")
        if self.host not in LOOPBACK and not self.production:
            out.append("listening on a non-loopback address outside production mode")
        if self.simulation:
            out.append("simulation mode: traffic and alerts are synthetic, not observed")
        return out
