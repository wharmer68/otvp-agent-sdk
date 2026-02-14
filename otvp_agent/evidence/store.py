"""Evidence Store — append-only, Merkle-tree-backed storage."""
from __future__ import annotations
import json, threading
from datetime import datetime, timezone
from pathlib import Path
from otvp_agent.crypto.keys import canonical_json
from otvp_agent.crypto.merkle import MerkleTree
from otvp_agent.evidence.models import SignedEvidence


class EvidenceStore:
    def __init__(self, persist_path: str | Path | None = None) -> None:
        self._items: list[SignedEvidence] = []
        self._tree = MerkleTree()
        self._index: dict[str, int] = {}
        self._lock = threading.Lock()
        self._persist_path = Path(persist_path) if persist_path else None
        if self._persist_path and self._persist_path.exists():
            self._load()

    @property
    def size(self) -> int: return len(self._items)

    @property
    def root_hash(self) -> str | None: return self._tree.root_hash

    def append(self, evidence: SignedEvidence) -> int:
        with self._lock:
            evidence.chain_sequence = len(self._items)
            if self._items:
                evidence.chain_previous_hash = self._items[-1].chain_leaf_hash
            leaf_data = canonical_json(evidence.to_verifiable_dict())
            leaf_hash = self._tree.append(leaf_data)
            evidence.chain_leaf_hash = leaf_hash
            idx = len(self._items)
            self._items.append(evidence)
            self._index[evidence.evidence_id] = idx
            if self._persist_path:
                self._persist_item(evidence)
            return idx

    def get(self, evidence_id: str) -> SignedEvidence | None:
        idx = self._index.get(evidence_id)
        return self._items[idx] if idx is not None else None

    def get_by_index(self, index: int) -> SignedEvidence:
        return self._items[index]

    def get_proof(self, index: int):
        return self._tree.get_proof(index)

    def get_proof_by_id(self, evidence_id: str):
        idx = self._index.get(evidence_id)
        return self._tree.get_proof(idx) if idx is not None else None

    def query(self, domain: str | None = None, limit: int = 100) -> list[SignedEvidence]:
        results = []
        for item in self._items:
            if domain and not item.domain.startswith(domain):
                continue
            results.append(item)
            if len(results) >= limit:
                break
        return results

    def export_chain_summary(self) -> dict:
        if not self._items:
            return {"total_items": 0, "merkle_root": None, "first_collected": None,
                    "last_collected": None, "domains_covered": []}
        domains = list({item.domain for item in self._items})
        return {
            "total_items": self.size, "merkle_root": self.root_hash,
            "first_collected": self._items[0].collected_at,
            "last_collected": self._items[-1].collected_at,
            "domains_covered": sorted(domains),
        }

    def _persist_item(self, evidence: SignedEvidence) -> None:
        with open(self._persist_path, "a") as f:
            f.write(json.dumps(evidence.to_dict()) + "\n")

    def _load(self) -> None:
        for line in self._persist_path.read_text().strip().split("\n"):
            if not line: continue
            d = json.loads(line)
            se = SignedEvidence(**{k: v for k, v in d.items()
                                   if k in SignedEvidence.__dataclass_fields__})
            leaf_data = canonical_json(se.to_verifiable_dict())
            self._tree.append(leaf_data)
            se.chain_leaf_hash = self._tree.leaves[-1]
            self._items.append(se)
            self._index[se.evidence_id] = len(self._items) - 1
