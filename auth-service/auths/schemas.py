from datetime import datetime, timedelta, timezone
from pydantic import BaseModel, Field, constr, model_validator, field_validator
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
    first_name: str | None = Field(default=None)
    last_name: str = Field(default="system")
    password: constr(min_length=8, strip_whitespace=True)
    is_admin: bool = Field(default=False)
    source: str = Field(default="manual")
    oa_id: str | None = Field(default=None)

    @model_validator(mode='before')
    def set_first_name(cls, values):
        if not values.get('first_name'):
            values['first_name'] = values.get('login')
        return values

    @model_validator(mode='before')
    def no_colon_in_login(cls, values):
        login = values.get('login')
        if login and ':' in login:
            raise ValueError("Login must not contain the ':' character")
        return values



class YandexUserInfo(BaseModel):
    id: str
    first_name: str
    last_name: str
