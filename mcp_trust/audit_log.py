"""
mcp_trust.audit_log
--------------------
Tamper-evident hash-chain audit log for attested tool interactions.

Each entry commits to the hash of the previous entry, so any retroactive
edit or deletion of a past entry breaks the chain from that point forward
and is detectable by verify(). This does not *prevent* tampering with the
log storage itself (that's a storage/access-control concern) -- it makes
tampering *evident*, which is the same guarantee enterprise reconciliation
logs provide.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any


GENESIS_HASH = "0" * 64


def _hash_entry(prev_hash: str, event: dict[str, Any], timestamp: float) -> str:
    payload = json.dumps(
        {"prev_hash": prev_hash, "event": event, "timestamp": timestamp},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


@dataclass
class AuditEntry:
    index: int
    event: dict[str, Any]
    timestamp: float
    prev_hash: str
    hash: str


@dataclass
class HashChainAuditLog:
    entries: list[AuditEntry] = field(default_factory=list)

    def append(self, event: dict[str, Any]) -> AuditEntry:
        prev_hash = self.entries[-1].hash if self.entries else GENESIS_HASH
        ts = time.time()
        h = _hash_entry(prev_hash, event, ts)
        entry = AuditEntry(
            index=len(self.entries), event=event, timestamp=ts, prev_hash=prev_hash, hash=h
        )
        self.entries.append(entry)
        return entry

    def verify(self) -> tuple[bool, int | None]:
        """
        Returns (is_valid, first_broken_index). first_broken_index is None
        if the chain is fully intact.
        """
        prev_hash = GENESIS_HASH
        for entry in self.entries:
            if entry.prev_hash != prev_hash:
                return False, entry.index
            expected = _hash_entry(entry.prev_hash, entry.event, entry.timestamp)
            if expected != entry.hash:
                return False, entry.index
            prev_hash = entry.hash
        return True, None

    def tamper_entry_for_testing(self, index: int, new_event: dict[str, Any]) -> None:
        """Test helper only: mutates an entry's event without recomputing the
        chain, simulating an attacker editing stored log data after the fact."""
        self.entries[index].event = new_event
