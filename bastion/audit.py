"""Tamper-evident action log: verify the hash chain written by store._insert_action.

Chain order is records.id ascending over kind='actions'. Each chained record carries
data.audit = {prev, hash} with hash = sha256(prev + "\n" + canonical_json(data without audit)).
Legacy rows without `audit` that precede the first chained record form an unchained prefix;
they are counted, not failed. An unchained row *after* the chain has started is an insertion.
"""
import json

from fastapi import APIRouter

from bastion import store

router = APIRouter(prefix="/__api/v1/audit")


def head():
    """{length: chained records, head: hash of the last chained record | None}."""
    with store.connection() as db:
        row = db.execute("SELECT COUNT(*) AS length, "
                         "(SELECT json_extract(data,'$.audit.hash') FROM records "
                         " WHERE kind='actions' AND json_extract(data,'$.audit.hash') IS NOT NULL "
                         " ORDER BY id DESC LIMIT 1) AS head "
                         "FROM records WHERE kind='actions' AND json_extract(data,'$.audit.hash') IS NOT NULL").fetchone()
    return {"length": row["length"], "head": row["head"]}


def verify():
    """Recompute the chain from genesis, streaming rows in id order.

    Detects modified data, deleted or reordered rows and inserted rows (any of these breaks
    the prev/hash links); `broken_at` is the id of the first record that fails. `length` and
    `head` describe the verified chain up to the break. A deleted *tail* is not detectable
    from the database alone (that is what external anchoring is for).
    """
    length, unchained, broken_at, prev = 0, 0, None, store.GENESIS_HASH
    with store.connection() as db:
        for row in db.execute("SELECT id, data FROM records WHERE kind='actions' ORDER BY id"):
            data = json.loads(row["data"])
            audit = data.pop("audit", None)
            if audit is None:
                if length == 0:
                    unchained += 1
                    continue
                broken_at = row["id"]
                break
            if not isinstance(audit, dict) or audit.get("prev") != prev \
                    or audit.get("hash") != store.action_hash(prev, data):
                broken_at = row["id"]
                break
            prev = audit["hash"]
            length += 1
    return {"intact": broken_at is None, "length": length, "head": prev if length else None,
            "unchained": unchained, "broken_at": broken_at, "checked_at": store.now()}


@router.get("/head")
def head_endpoint():
    return head()


@router.get("/verify")
def verify_endpoint():
    return verify()
