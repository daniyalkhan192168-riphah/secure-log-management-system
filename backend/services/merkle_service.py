"""
Merkle tree over log entry hashes, with domain separation:
    leaf  = SHA256(0x00 || entry_hash)
    node  = SHA256(0x01 || left || right)
An odd node at the end of a level is promoted unchanged (NOT duplicated),
which avoids the CVE-2012-2459 style ambiguity of the old implementation.
"""
import hashlib


def _leaf(h_hex: str) -> bytes:
    return hashlib.sha256(b"\x00" + bytes.fromhex(h_hex)).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def build_levels(entry_hashes: list) -> list:
    """All levels as raw bytes, from leaves (index 0) up to the root."""
    if not entry_hashes:
        return []
    level = [_leaf(h) for h in entry_hashes]
    levels = [level]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(_node(level[i], level[i + 1]))
            else:
                nxt.append(level[i])  # promote odd node
        level = nxt
        levels.append(level)
    return levels


def build_merkle_root(entry_hashes: list):
    levels = build_levels(entry_hashes)
    return levels[-1][0].hex() if levels else None


def inclusion_proof(entry_hashes: list, index: int) -> list:
    """Audit path for the leaf at `index`: list of {"sibling", "position"}."""
    proof = []
    levels = build_levels(entry_hashes)
    for level in levels[:-1]:
        sibling = index ^ 1
        if sibling < len(level):
            proof.append({
                "sibling": level[sibling].hex(),
                "position": "left" if sibling < index else "right",
            })
        index //= 2
    return proof


def verify_inclusion(entry_hash_hex: str, proof: list, root_hex: str) -> bool:
    current = _leaf(entry_hash_hex)
    for step in proof:
        sib = bytes.fromhex(step["sibling"])
        current = _node(sib, current) if step["position"] == "left" else _node(current, sib)
    return current.hex() == root_hex


def tree_for_display(entry_hashes: list) -> list:
    """Levels from root to leaves with shortened hashes (for the dashboard)."""
    short = lambda b: b.hex()[:8] + "..." + b.hex()[-6:]
    return [[short(n) for n in level] for level in reversed(build_levels(entry_hashes))]
