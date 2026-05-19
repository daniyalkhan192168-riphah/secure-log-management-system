import hashlib
import json

def generate_hash(log_data: dict, previous_hash: str = "GENESIS") -> str:
    data_string = json.dumps(log_data, sort_keys=True) + previous_hash
    return hashlib.sha256(data_string.encode()).hexdigest()