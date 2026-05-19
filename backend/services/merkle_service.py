import hashlib

def hash_pair(left: str, right: str) -> str:
    return hashlib.sha256((left + right).encode()).hexdigest()


def build_merkle_root(hashes: list[str]):
    if not hashes:
        return None

    current_level = hashes[:]

    while len(current_level) > 1:
        if len(current_level) % 2 == 1:
            current_level.append(current_level[-1])

        next_level = []

        for i in range(0, len(current_level), 2):
            combined_hash = hash_pair(current_level[i], current_level[i + 1])
            next_level.append(combined_hash)

        current_level = next_level

    return current_level[0]