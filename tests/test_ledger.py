import json
import os
import threading

import pytest

from adaptive_merkle_tree import AdaptiveMerkleTree
from blockaudit.ledger import Ledger, LedgerLocked, block_hash


@pytest.fixture
def ledger(tmp_path):
    lg = Ledger(str(tmp_path / "chain.json"))
    yield lg
    lg.close()


def fill(lg, n=5):
    for i in range(n):
        lg.append({"event_type": "T", "n": i})


def rewrite(path, fn):
    lines = [json.loads(x) for x in open(path).read().splitlines() if x]
    fn(lines)
    with open(path, "w") as f:
        for b in lines:
            f.write(json.dumps(b, sort_keys=True) + "\n")


def test_append_and_verify(ledger):
    fill(ledger)
    res = ledger.verify_disk()
    assert res["valid"] and res["block_count"] == 6
    assert res["checks"]["checkpoint"] == "matched" and res["checks"]["memory_copy"] == "matched"


def test_reload_persists(tmp_path):
    p = str(tmp_path / "c.json")
    a = Ledger(p)
    fill(a, 3)
    tip = a.tip()["hash"]
    a.close()
    b = Ledger(p)
    assert len(b) == 4 and b.tip()["hash"] == tip
    b.close()


def test_altered_payload_detected(ledger):
    fill(ledger)
    rewrite(ledger.path, lambda bl: bl[2].update(data='{"forged":1}'))
    res = ledger.verify_disk()
    assert not res["valid"]
    checks = {(f["index"], f["check"]) for f in res["failures"]}
    assert (2, "hash_mismatch") in checks and (2, "diverged_from_memory") in checks
    assert res["first_failure_index"] == 2


def test_changed_hash_breaks_link(ledger):
    fill(ledger)
    rewrite(ledger.path, lambda bl: bl[2].update(hash="f" * 64))
    res = ledger.verify_disk()
    assert {"hash_mismatch", "link_broken"} <= {f["check"] for f in res["failures"]}


def test_reordered_records_detected(ledger):
    fill(ledger)
    rewrite(ledger.path, lambda bl: bl.insert(2, bl.pop(3)))
    assert not ledger.verify_disk()["valid"]


def test_missing_record_detected(ledger):
    fill(ledger)
    rewrite(ledger.path, lambda bl: bl.pop(3))
    res = ledger.verify_disk()
    assert not res["valid"]
    assert any(f["check"] in ("link_broken", "index") for f in res["failures"])


def test_truncation_detected_by_checkpoint(ledger):
    fill(ledger)
    rewrite(ledger.path, lambda bl: bl.__delitem__(slice(4, None)))
    res = ledger.verify_disk()
    assert any(f["check"] == "truncated" for f in res["failures"])


def test_full_rewrite_with_recomputed_hashes_caught_by_checkpoint_and_memory(ledger):
    fill(ledger)

    def forge(bl):
        bl[2]["data"] = '{"forged":1}'
        for i in range(2, len(bl)):
            bl[i]["previous_hash"] = bl[i - 1]["hash"] if i > 2 else bl[1]["hash"]
            bl[i]["hash"] = block_hash(bl[i])
    rewrite(ledger.path, forge)
    res = ledger.verify_disk()
    checks = {f["check"] for f in res["failures"]}
    assert "history_rewritten" in checks and "diverged_from_memory" in checks
    assert "hash_mismatch" not in checks


def test_partial_tail_is_quarantined_not_fatal(tmp_path):
    p = str(tmp_path / "c.json")
    a = Ledger(p)
    fill(a, 3)
    a.close()
    with open(p, "ab") as f:
        f.write(b'{"index": 4, "timest')
    b = Ledger(p)
    assert len(b) == 4 and b.recovery["kind"] == "truncated_partial_tail"
    assert any(n.startswith("c.json.recovered-") for n in os.listdir(tmp_path))
    b.append({"x": 1})
    assert b.verify_disk()["valid"]
    b.close()


def test_corrupt_middle_is_quarantined_and_chain_restarts(tmp_path):
    p = str(tmp_path / "c.json")
    a = Ledger(p)
    fill(a, 4)
    a.close()
    lines = open(p).read().splitlines()
    lines[2] = "garbage"
    open(p, "w").write("\n".join(lines) + "\n")
    b = Ledger(p)
    assert b.recovery["kind"] == "quarantined_corrupt_ledger"
    assert any(n.startswith("c.json.corrupt-") for n in os.listdir(tmp_path))
    assert "LEDGER_RESTART" in b.get(1)["data"]
    b.close()


def test_legacy_json_array_is_migrated_and_still_verifies(tmp_path):
    p = str(tmp_path / "old.json")
    g = {"index": 0, "timestamp": "2026-01-01T00:00:00", "data": "Genesis", "previous_hash": "0", "hash": ""}
    g["hash"] = block_hash(g)
    b1 = {"index": 1, "timestamp": "2026-01-01T00:00:01", "data": "{}", "previous_hash": g["hash"], "hash": ""}
    b1["hash"] = block_hash(b1)
    json.dump([g, b1], open(p, "w"), indent=2)
    lg = Ledger(p)
    assert lg.recovery["kind"] == "migrated_legacy_json" and os.path.exists(p + ".legacy.bak")
    assert lg.verify_disk()["valid"] and len(lg) == 2
    lg.close()


def test_second_process_cannot_open_same_ledger(ledger):
    with pytest.raises(LedgerLocked):
        Ledger(ledger.path)


def test_concurrent_appends_keep_chain_valid(ledger):
    def work(k):
        for i in range(25):
            ledger.append({"t": k, "i": i})
    ts = [threading.Thread(target=work, args=(k,)) for k in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert len(ledger) == 201 and ledger.verify_disk()["valid"]


def test_write_failure_does_not_extend_memory(ledger, monkeypatch):
    fill(ledger, 2)
    import blockaudit.ledger as mod

    def boom(fd):
        raise OSError("disk full")
    monkeypatch.setattr(mod.os, "fsync", boom)
    with pytest.raises(mod.LedgerError):
        ledger.append({"x": 1})
    monkeypatch.undo()
    assert len(ledger) == 3 and ledger.status()["last_write_error"]
    assert ledger.verify_disk()["valid"]


def test_merkle_proofs_valid_for_every_index_including_odd_levels():
    for n in (1, 2, 3, 5, 7, 8, 13):
        t = AdaptiveMerkleTree()
        for i in range(n):
            t.add_leaf(f"leaf{i}")
        t.build()
        for i in range(n):
            import hashlib
            leaf = hashlib.sha256(f"leaf{i}".encode()).hexdigest()
            assert t.verify(leaf, t.get_proof(i), t.get_root()), (n, i)


def test_merkle_proof_rejects_wrong_leaf(ledger):
    fill(ledger, 4)
    p = ledger.merkle_proof(2)
    assert p["valid"]
    t = AdaptiveMerkleTree()
    assert not t.verify("0" * 64, [(x["sibling"], x["leaf_is_left"]) for x in p["path"]], p["root"])


def test_merkle_optimize_keeps_all_leaves():
    t = AdaptiveMerkleTree()
    for i in range(5):
        t.add_leaf(f"x{i}")
    t.access_freq[3] += 4
    t.optimize()
    assert len(t.leaves) == 5 and len(set(t.leaves)) == 5
