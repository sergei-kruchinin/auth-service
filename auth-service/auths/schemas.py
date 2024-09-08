# schemas.py
from datetime import datetime, timedelta, timezone
from pydantic import BaseModel, Field, constr, model_validator, ConfigDict
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
    login: constr(min_length=3, strip_whitespace=True) = Field(
        ..., description="The login of the user"
    )
    password: constr(min_length=8, strip_whitespace=True) = Field(
        ..., description="The plaintext password of the user"
    )


class UserBaseSchema(BaseModel):
    login: constr(min_length=3, strip_whitespace=True)
    first_name: str | None = Field(default=None, description="The first name of the user")
    last_name: str = Field(default="system", description="The last name of the user")
    password: (constr(min_length=8, strip_whitespace=True)
               | None) = Field(default=None, description="The plaintext password provided by the user or None.")
    is_admin: bool = Field(default=False, description="Boolean indicating if the user is an admin.")
    source: str = Field(default="manual", description="The source of the user (manual/yandex)")
    oa_id: str | None = Field(default=None, description="The OAuth ID.")


class UserCreateSchema(UserBaseSchema):
    pass


class OauthUserCreateSchema(UserBaseSchema):
    @model_validator(mode='before')
    def set_composite_login(values):
        if 'login' not in values or not values['login']:
            values['login'] = f"{values.get('source')}:{values.get('oa_id')}"
        return values


class UserCreateInputSchema(UserBaseSchema):

    @model_validator(mode='before')
    def set_first_name(values):
        if not values.get('first_name'):
            values['first_name'] = values.get('login')
        return values

    @model_validator(mode='before')
    def no_colon_in_login(values):
        login = values.get('login')
        if login and ':' in login:
            raise ValueError("Login must not contain the ':' character")
        return values


class UserResponseSchema(UserBaseSchema):
    id: int
    # created_at: str
    # updated_at: str | None = None
    model_config = ConfigDict(from_attributes=True)


class YandexUserInfo(BaseModel):
    id: str
    first_name: str
    last_name: str
