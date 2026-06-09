import hashlib

def hash_pair(left: str, right: str) -> str:
    return hashlib.sha256((left + right).encode()).hexdigest()


def build_merkle_root(hashes: list) -> str:
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


def build_merkle_tree(hashes: list) -> list:
    if not hashes:
        return []

    # Store all levels from leaves to root
    levels = []
    current_level = hashes[:]

    # Shorten hashes for display
    def shorten(h):
        return h[:8] + "..." + h[-6:]

    levels.append([shorten(h) for h in current_level])

    while len(current_level) > 1:
        if len(current_level) % 2 == 1:
            current_level.append(current_level[-1])

        next_level = []
        for i in range(0, len(current_level), 2):
            combined = hash_pair(current_level[i], current_level[i + 1])
            next_level.append(combined)

        current_level = next_level
        levels.append([shorten(h) for h in current_level])

    # Return levels from root to leaves
    levels.reverse()
    return levels