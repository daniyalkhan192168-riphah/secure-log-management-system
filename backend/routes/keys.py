from fastapi import APIRouter
from pydantic import BaseModel
from services.key_manager import get_current_key_state, evolve_key


router = APIRouter(
    prefix="/keys",
    tags=["Forward Secure Key Management"]
)


class KeyStateResponse(BaseModel):
    status: str
    key_version: int
    current_key_hash: str
    created_at: str
    updated_at: str


@router.get("/current", response_model=KeyStateResponse)
def current_key():
    state = get_current_key_state()

    return {
        "status": "success",
        "key_version": state["key_version"],
        "current_key_hash": state["current_key_hash"],
        "created_at": state["created_at"],
        "updated_at": state["updated_at"]
    }


@router.post("/evolve", response_model=KeyStateResponse)
def evolve_forward_secure_key():
    state = evolve_key()

    return {
        "status": "Key evolved successfully",
        "key_version": state["key_version"],
        "current_key_hash": state["current_key_hash"],
        "created_at": state["created_at"],
        "updated_at": state["updated_at"]
    }