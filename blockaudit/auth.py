import hashlib
import hmac
import time
from collections import defaultdict, deque
from threading import Lock

ROLES = {"viewer": 1, "analyst": 2, "admin": 3}


class Principal:
    def __init__(self, role, ident):
        self.role = role
        self.id = ident

    def allows(self, role):
        return ROLES[self.role] >= ROLES[role]


class Authenticator:
    def __init__(self, tokens):
        self._digests = {role: hashlib.sha256(t.encode()).digest() for role, t in tokens.items()}

    def check(self, token):
        if not token:
            return None
        digest = hashlib.sha256(token.encode()).digest()
        found = None
        for role, expected in self._digests.items():
            if hmac.compare_digest(digest, expected):
                found = role
        if found is None:
            return None
        return Principal(found, f"{found}:{digest.hex()[:8]}")


def bearer_token(headers, query_token=None):
    value = headers.get("Authorization", "")
    if value.lower().startswith("bearer "):
        return value[7:].strip()
    return query_token


class RateLimiter:
    def __init__(self, clock=time.monotonic):
        self._hits = defaultdict(deque)
        self._lock = Lock()
        self._clock = clock

    def allow(self, key, limit, window=60.0):
        now = self._clock()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] > window:
                q.popleft()
            if len(q) >= limit:
                return False, max(1, int(window - (now - q[0])))
            q.append(now)
            if len(self._hits) > 10000:
                for k in [k for k, v in self._hits.items() if not v]:
                    del self._hits[k]
            return True, 0
