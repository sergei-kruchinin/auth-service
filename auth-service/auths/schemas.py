from datetime import datetime, timedelta, timezone
from pydantic import BaseModel, Field, constr, field_validator
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


class UserCreateSchema(BaseModel):
    login: constr(min_length=3, strip_whitespace=True)
    first_name: str = Field(default="user")
    last_name: str = Field(default="system")
    password: constr(min_length=8, strip_whitespace=True)
    is_admin: bool = Field(default=False)

