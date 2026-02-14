"""Merkle tree for tamper-evident evidence chaining."""
from __future__ import annotations
import hashlib
from dataclasses import dataclass, field


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def hash_pair(left: str, right: str) -> str:
    combined = min(left, right) + max(left, right)
    return sha256(combined.encode("utf-8"))


@dataclass
class MerkleProof:
    leaf_hash: str
    proof_hashes: list[tuple[str, str]]
    root_hash: str

    def verify(self) -> bool:
        current = self.leaf_hash
        for sibling_hash, direction in self.proof_hashes:
            if direction == "left":
                current = hash_pair(sibling_hash, current)
            else:
                current = hash_pair(current, sibling_hash)
        return current == self.root_hash

    def to_dict(self) -> dict:
        return {"leaf_hash": self.leaf_hash,
                "proof_hashes": [{"hash": h, "direction": d} for h, d in self.proof_hashes],
                "root_hash": self.root_hash}


@dataclass
class MerkleTree:
    leaves: list[str] = field(default_factory=list)
    _levels: list[list[str]] = field(default_factory=list, repr=False)

    @property
    def root_hash(self) -> str | None:
        if not self.leaves: return None
        if not self._levels: self._rebuild()
        return self._levels[-1][0]

    @property
    def size(self) -> int:
        return len(self.leaves)

    def append(self, data: bytes) -> str:
        leaf_hash = sha256(data)
        self.leaves.append(leaf_hash)
        self._rebuild()
        return leaf_hash

    def get_proof(self, index: int) -> MerkleProof:
        if not self._levels: self._rebuild()
        proof_hashes = []
        idx = index
        for level in self._levels[:-1]:
            if idx % 2 == 0:
                if idx + 1 < len(level):
                    proof_hashes.append((level[idx + 1], "right"))
            else:
                proof_hashes.append((level[idx - 1], "left"))
            idx //= 2
        return MerkleProof(leaf_hash=self.leaves[index], proof_hashes=proof_hashes, root_hash=self.root_hash)

    def verify_leaf(self, index: int, data: bytes) -> bool:
        expected = sha256(data)
        if index >= len(self.leaves) or self.leaves[index] != expected:
            return False
        return self.get_proof(index).verify()

    def _rebuild(self) -> None:
        if not self.leaves:
            self._levels = []
            return
        levels: list[list[str]] = [list(self.leaves)]
        current = levels[0]
        while len(current) > 1:
            next_level = []
            for i in range(0, len(current), 2):
                if i + 1 < len(current):
                    next_level.append(hash_pair(current[i], current[i + 1]))
                else:
                    next_level.append(current[i])
            levels.append(next_level)
            current = next_level
        self._levels = levels

    def to_dict(self) -> dict:
        return {"leaves": self.leaves, "root_hash": self.root_hash, "size": self.size}
