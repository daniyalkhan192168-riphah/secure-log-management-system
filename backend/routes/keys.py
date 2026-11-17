from fastapi import APIRouter, Depends

from config import BATCH_SIZE
from security import require_admin
from services import key_manager as km

router = APIRouter(prefix="/keys", tags=["Forward Secure Key Management"],
                   dependencies=[Depends(require_admin)])


@router.get("/current")
def current_key():
    """Public key metadata only. The secret key is NEVER returned."""
    state = km.public_state()
    return {
        "status": "success",
        "key_version": state["key_version"],
        "k0_fingerprint": state["k0_fingerprint"],
        "created_at": state["created_at"],
        "updated_at": state["updated_at"],
        "evolution": "K(b+1) = SHA256('SLv1-evolve' || K(b)); old key overwritten",
        "evolves_when": f"a batch is sealed (every {BATCH_SIZE} logs, or via POST /merkle/seal)",
    }