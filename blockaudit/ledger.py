import copy
import fcntl
import hashlib
import json
import os
import shutil
import threading
from collections import deque
from datetime import datetime, timezone

from adaptive_merkle_tree import AdaptiveMerkleTree

GENESIS_DATA = "Genesis Block - Network Security Audit System"
FIELDS = ("index", "timestamp", "data", "previous_hash", "hash")

LIMITATIONS = (
    "a hash chain detects edits that leave hashes inconsistent. a writer who can rewrite the whole "
    "file and the checkpoint can recompute every hash; retain checkpoints on a separate system to detect that"
)


class LedgerError(Exception):
    pass


class LedgerLocked(LedgerError):
    pass


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def block_hash(block):
    # same canonical form as the original ledger so existing chains still verify
    payload = json.dumps({
        "index": block["index"],
        "timestamp": block["timestamp"],
        "data": block["data"],
        "previous_hash": block["previous_hash"],
    }, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()


def _failure(index, check, detail, expected=None, actual=None):
    f = {"index": index, "check": check, "detail": detail}
    if expected is not None:
        f["expected"] = expected
    if actual is not None:
        f["actual"] = actual
    return f


def verify_blocks(blocks, checkpoint=None, memory=None):
    """check every block, not only the tip. returns a result dict with precise failures"""
    failures = []
    if not blocks:
        failures.append(_failure(None, "empty", "ledger contains no blocks"))
    seen = {}
    for i, b in enumerate(blocks):
        if not isinstance(b, dict) or any(k not in b for k in FIELDS) or not all(
                isinstance(b[k], (str if k != "index" else int)) for k in FIELDS):
            failures.append(_failure(i, "malformed", "block is missing fields or has wrong types"))
            continue
        if b["index"] != i:
            failures.append(_failure(i, "index", "block index does not match its position", i, b["index"]))
        calc = block_hash(b)
        if calc != b["hash"]:
            failures.append(_failure(i, "hash_mismatch", "stored hash does not match block contents",
                                     calc, b["hash"]))
        if i == 0:
            if b["previous_hash"] != "0":
                failures.append(_failure(i, "genesis", "genesis previous_hash must be '0'", "0", b["previous_hash"]))
        elif isinstance(blocks[i - 1], dict) and b["previous_hash"] != blocks[i - 1].get("hash"):
            failures.append(_failure(i, "link_broken", "previous_hash does not match the preceding block",
                                     blocks[i - 1].get("hash"), b["previous_hash"]))
        if b["hash"] in seen:
            failures.append(_failure(i, "duplicate", f"hash repeats block {seen[b['hash']]}"))
        seen[b["hash"]] = i

    checkpoint_state = "unavailable"
    if checkpoint:
        n = checkpoint.get("count", 0)
        if len(blocks) < n:
            checkpoint_state = "mismatch"
            failures.append(_failure(None, "truncated",
                                     f"ledger has {len(blocks)} blocks but the checkpoint recorded {n}", n, len(blocks)))
        elif n and isinstance(blocks[n - 1], dict) and blocks[n - 1].get("hash") != checkpoint.get("tip_hash"):
            checkpoint_state = "mismatch"
            failures.append(_failure(n - 1, "history_rewritten",
                                     "block hash differs from the independently recorded checkpoint",
                                     checkpoint.get("tip_hash"), blocks[n - 1].get("hash")))
        else:
            checkpoint_state = "matched"

    memory_state = "unavailable"
    if memory is not None:
        memory_state = "matched"
        for i, m in enumerate(memory):
            if i >= len(blocks):
                failures.append(_failure(i, "missing_vs_memory", "block held by the running service is absent on disk"))
                memory_state = "mismatch"
                break
            if isinstance(blocks[i], dict) and any(blocks[i].get(k) != m[k] for k in FIELDS):
                failures.append(_failure(i, "diverged_from_memory",
                                         "on-disk block differs from the copy held by the running service",
                                         m["hash"], blocks[i].get("hash")))
                memory_state = "mismatch"

    valid = not failures
    first = next((f["index"] for f in failures if f["index"] is not None), None)
    return {
        "valid": valid,
        "block_count": len(blocks),
        "checked_blocks": len(blocks),
        "checked_at": utcnow(),
        "failures": failures[:50],
        "failure_count": len(failures),
        "first_failure_index": first,
        "checks": {"hash_recomputed": True, "links": True, "indices": True,
                   "checkpoint": checkpoint_state, "memory_copy": memory_state},
        "message": "all blocks verified" if valid else
                   f"{len(failures)} integrity failure(s), first at block {first}" if first is not None else
                   f"{len(failures)} integrity failure(s)",
        "limitations": LIMITATIONS,
    }


def _fsync_dir(path):
    try:
        fd = os.open(os.path.dirname(os.path.abspath(path)) or ".", os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


def atomic_write(path, data: bytes):
    tmp = f"{path}.tmp.{os.getpid()}"
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    _fsync_dir(path)


class Ledger:
    """append-only hash chain stored one json block per line. appends are fsynced before they return"""

    def __init__(self, path, checkpoint_path=None, fsync=True):
        self.path = path
        self.checkpoint_path = checkpoint_path or path + ".checkpoint"
        self.fsync = fsync
        self._lock = threading.RLock()
        self._blocks = []
        self._merkle = AdaptiveMerkleTree()
        self._merkle_dirty = False
        self.history = deque(maxlen=100)
        self.last_verification = None
        self.recovery = None
        self.last_error = None
        self.checkpoint_error = None
        self._lockfd = None
        self._expected_stat = None

        d = os.path.dirname(os.path.abspath(path))
        os.makedirs(d, exist_ok=True)
        self._acquire_process_lock()
        try:
            self._load()
        except Exception:
            self.close()
            raise

    def _acquire_process_lock(self):
        fd = os.open(self.path + ".lock", os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            raise LedgerLocked(f"another process already owns ledger {self.path}")
        self._lockfd = fd

    def close(self):
        if self._lockfd is not None:
            try:
                fcntl.flock(self._lockfd, fcntl.LOCK_UN)
                os.close(self._lockfd)
            finally:
                self._lockfd = None

    def _load(self):
        if not os.path.exists(self.path) or os.path.getsize(self.path) == 0:
            self._blocks = [self._make_block(0, GENESIS_DATA, "0")]
            atomic_write(self.path, self._encode(self._blocks))
            self._rebuild_merkle()
            self._write_checkpoint()
            self._expected_stat = self._file_stat()
            return
        with open(self.path, "rb") as f:
            raw = f.read()
        blocks, bad = self._parse(raw)
        if bad is not None and bad["kind"] == "legacy":
            self._migrate_legacy(blocks, bad["backup"])
        elif bad is not None:
            blocks = self._recover(raw, blocks, bad)
        self._blocks = blocks
        self._rebuild_merkle()
        self._expected_stat = self._file_stat()
        if not os.path.exists(self.checkpoint_path):
            self._write_checkpoint()

    @staticmethod
    def _encode(blocks):
        return b"".join(json.dumps(b, sort_keys=True).encode() + b"\n" for b in blocks)

    def _parse(self, raw):
        text = raw.lstrip()
        if text.startswith(b"["):
            try:
                arr = json.loads(raw)
            except ValueError as e:
                return [], {"kind": "middle", "line": 0, "offset": 0, "error": str(e)}
            return arr, {"kind": "legacy", "backup": self.path + ".legacy.bak"}
        blocks, offset = [], 0
        lines = raw.split(b"\n")
        for n, line in enumerate(lines):
            if not line.strip():
                offset += len(line) + 1
                continue
            try:
                obj = json.loads(line)
                if not isinstance(obj, dict):
                    raise ValueError("not an object")
            except ValueError as e:
                last = all(not rest.strip() for rest in lines[n + 1:])
                return blocks, {"kind": "tail" if last else "middle", "line": n + 1, "offset": offset, "error": str(e)}
            blocks.append(obj)
            offset += len(line) + 1
        return blocks, None

    def _migrate_legacy(self, blocks, backup):
        shutil.copy2(self.path, backup)
        atomic_write(self.path, self._encode(blocks))
        self.recovery = {"kind": "migrated_legacy_json", "at": utcnow(), "backup": os.path.basename(backup),
                         "blocks": len(blocks)}

    def _recover(self, raw, good, bad):
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        if bad["kind"] == "tail":
            side = f"{self.path}.recovered-{stamp}"
            with open(side, "wb") as f:
                f.write(raw[bad["offset"]:])
            atomic_write(self.path, self._encode(good))
            self.recovery = {"kind": "truncated_partial_tail", "at": utcnow(), "line": bad["line"],
                             "quarantined_to": os.path.basename(side), "kept_blocks": len(good)}
            return good
        side = f"{self.path}.corrupt-{stamp}"
        os.replace(self.path, side)
        tip = good[-1]["hash"] if good else None
        note = json.dumps({"event_type": "LEDGER_RESTART", "reason": "unparseable record in the middle of the ledger",
                           "quarantined_file": os.path.basename(side), "last_good_count": len(good),
                           "last_good_tip": tip}, sort_keys=True)
        fresh = [self._make_block(0, GENESIS_DATA, "0")]
        fresh.append(self._make_block(1, note, fresh[0]["hash"]))
        atomic_write(self.path, self._encode(fresh))
        self.recovery = {"kind": "quarantined_corrupt_ledger", "at": utcnow(), "line": bad["line"],
                         "quarantined_to": os.path.basename(side), "last_good_count": len(good)}
        return fresh

    @staticmethod
    def _make_block(index, data, previous_hash):
        b = {"index": index, "timestamp": utcnow(), "data": data, "previous_hash": previous_hash, "hash": ""}
        b["hash"] = block_hash(b)
        return b

    def _rebuild_merkle(self):
        self._merkle = AdaptiveMerkleTree()
        for b in self._blocks:
            if isinstance(b, dict) and isinstance(b.get("hash"), str):
                self._merkle.add_leaf(b["hash"], hashed=False)
        self._merkle.build()
        self._merkle_dirty = False

    def _write_checkpoint(self):
        tip = self._blocks[-1]
        cp = {"count": len(self._blocks), "tip_hash": tip["hash"], "written_at": utcnow()}
        try:
            atomic_write(self.checkpoint_path, json.dumps(cp, sort_keys=True).encode())
            self.checkpoint_error = None
        except OSError as e:
            self.checkpoint_error = str(e)

    def read_checkpoint(self):
        try:
            with open(self.checkpoint_path, "rb") as f:
                cp = json.loads(f.read())
            if isinstance(cp, dict) and isinstance(cp.get("count"), int) and isinstance(cp.get("tip_hash"), str):
                return cp
        except (OSError, ValueError):
            pass
        return None

    def append(self, event):
        data = event if isinstance(event, str) else json.dumps(event, sort_keys=True)
        with self._lock:
            prev = self._blocks[-1]
            block = self._make_block(len(self._blocks), data, prev["hash"])
            line = json.dumps(block, sort_keys=True).encode() + b"\n"
            try:
                size = os.path.getsize(self.path)
                with open(self.path, "ab") as f:
                    try:
                        f.write(line)
                        f.flush()
                        if self.fsync:
                            os.fsync(f.fileno())
                    except OSError:
                        f.truncate(size)
                        raise
            except OSError as e:
                self.last_error = {"at": utcnow(), "error": str(e)}
                raise LedgerError(f"ledger write failed: {e}") from e
            self.last_error = None
            self._blocks.append(block)
            self._merkle.add_leaf(block["hash"], hashed=False)
            self._merkle_dirty = True
            self._write_checkpoint()
            self._expected_stat = self._file_stat()
            return copy.deepcopy(block)

    def _file_stat(self):
        try:
            st = os.stat(self.path)
            return (st.st_size, st.st_mtime_ns)
        except OSError:
            return None

    def expected_stat(self):
        with self._lock:
            return self._expected_stat

    def __len__(self):
        return len(self._blocks)

    def get(self, index):
        with self._lock:
            if 0 <= index < len(self._blocks):
                return copy.deepcopy(self._blocks[index])
        return None

    def tip(self):
        with self._lock:
            return copy.deepcopy(self._blocks[-1])

    def blocks(self, offset=0, limit=50, newest_first=True):
        with self._lock:
            n = len(self._blocks)
            if newest_first:
                hi = n - offset
                lo = max(0, hi - limit)
                return [copy.deepcopy(b) for b in reversed(self._blocks[lo:max(hi, 0)])]
            return [copy.deepcopy(b) for b in self._blocks[offset:offset + limit]]

    def search(self, predicate, offset=0, limit=25):
        """newest-first scan; copies only the page that is returned"""
        with self._lock:
            hits, total = [], 0
            for b in reversed(self._blocks):
                if predicate(b):
                    if offset <= total < offset + limit:
                        hits.append(copy.deepcopy(b))
                    total += 1
            return hits, total

    def all_blocks(self):
        with self._lock:
            return copy.deepcopy(self._blocks)

    def _merkle_ready(self):
        if self._merkle_dirty:
            self._merkle.build()
            self._merkle_dirty = False

    def merkle_root(self):
        with self._lock:
            self._merkle_ready()
            return self._merkle.get_root()

    def merkle_proof(self, index):
        with self._lock:
            if not 0 <= index < len(self._blocks):
                return None
            self._merkle_ready()
            proof = self._merkle.get_proof(index)
            root = self._merkle.get_root()
            leaf = self._blocks[index]["hash"]
            return {"index": index, "leaf": leaf, "root": root,
                    "path": [{"sibling": s, "leaf_is_left": left} for s, left in proof],
                    "valid": self._merkle.verify(leaf, proof, root)}

    def verify_memory(self):
        with self._lock:
            return self._record(verify_blocks(self._blocks, self.read_checkpoint()), "memory")

    def verify_disk(self):
        """re-read the file and compare it with the copy this process holds"""
        with self._lock:
            memory = copy.deepcopy(self._blocks)
            try:
                with open(self.path, "rb") as f:
                    raw = f.read()
            except OSError as e:
                res = verify_blocks([], None)
                res["failures"] = [_failure(None, "unreadable", f"ledger file cannot be read: {e}")]
                res["failure_count"] = 1
                res["message"] = "ledger file is missing or unreadable"
                return self._record(res, "disk")
            blocks, bad = self._parse(raw)
            res = verify_blocks(blocks, self.read_checkpoint(), memory=memory)
            if bad is not None and bad["kind"] != "legacy":
                res["valid"] = False
                res["failures"].insert(0, _failure(None, "unparseable",
                                                   f"line {bad['line']} is not valid json: {bad['error'][:80]}"))
                res["failure_count"] += 1
                res["message"] = "ledger file contains unparseable records"
            return self._record(res, "disk")

    def _record(self, result, source):
        result["source"] = source
        self.last_verification = result
        self.history.append({k: result[k] for k in ("checked_at", "valid", "block_count", "failure_count",
                                                    "first_failure_index", "source", "message")})
        return result

    def status(self):
        with self._lock:
            lv = self.last_verification
            return {
                "block_count": len(self._blocks),
                "tip_hash": self._blocks[-1]["hash"],
                "merkle_root": self.merkle_root(),
                "last_verification": lv,
                "recovery": self.recovery,
                "last_write_error": self.last_error,
                "checkpoint_error": self.checkpoint_error,
                "durability": "fsync per append" if self.fsync else "no fsync",
                "limitations": LIMITATIONS,
            }
