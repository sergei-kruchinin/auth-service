from datetime import datetime, timedelta, timezone
from pydantic import BaseModel, Field, constr
import os

EXPIRES_SECONDS = int(os.getenv('EXPIRES_SECONDS'))

# Pydantic models
class AuthPayload(BaseModel):
    id: int
    login: str
    first_name: str
    last_name: str
    is_admin: bool
    exp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc) + timedelta(seconds=EXPIRES_SECONDS))


class AuthResponse(BaseModel):
    token: str
    expires_in: int

class AuthRequest(BaseModel):
    login: constr(min_length=3, strip_whitespace=True)
    password: constr(min_length=8, strip_whitespace=True)