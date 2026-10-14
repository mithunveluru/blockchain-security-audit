import json
import logging
import re
import sys

_SECRETS = re.compile(r"(?i)(bearer\s+|token[=:\s\"']+|api[_-]?key[=:\s\"']+|x-api-key[=:\s\"']+)([A-Za-z0-9._~+/=-]{8,})")
_KEYS = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)


def redact(text):
    return _KEYS.sub("[private key redacted]", _SECRETS.sub(lambda m: m.group(1) + "[redacted]", str(text)))


class JsonFormatter(logging.Formatter):
    def format(self, record):
        msg = redact(record.getMessage())
        out = {"time": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"), "level": record.levelname,
               "logger": record.name, "message": msg}
        extra = getattr(record, "fields", None)
        if extra:
            out.update({k: redact(v) if isinstance(v, str) else v for k, v in extra.items()})
        if record.exc_info:
            out["exception"] = redact(self.formatException(record.exc_info))
        return json.dumps(out)


def setup(level="INFO"):
    root = logging.getLogger("blockaudit")
    if root.handlers:
        return root
    h = logging.StreamHandler(sys.stderr)
    h.setFormatter(JsonFormatter())
    root.addHandler(h)
    root.setLevel(level)
    root.propagate = False
    return root
