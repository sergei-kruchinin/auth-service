# core > schemas.py
from datetime import datetime
from pydantic import BaseModel, Field, constr, model_validator, ConfigDict
from typing import Dict


# Pydantic models


class TokenPayload(BaseModel):
    id: int = Field(..., description="User id in our database")
    login: str = Field(..., description="Login of user, incl. composite login <oa:id>")
    first_name: str = Field(..., description="The first name of user, for system users can be == login")
    last_name: str = Field(..., description="The first name of user, for system users can be 'system'")
    is_admin: bool = Field(default=False, description="Boolean indicating if the user is a system superuser.")
    device_fingerprint: str = Field(default=None, description="Device/browser fingerprint: <useragent:lang>")
    exp: datetime = Field(default=None, description="The value will be set by token generation")


class TokenData(BaseModel):
    value: str
    expires_in: int


class AuthResponse(BaseModel):
    tokens: Dict[str, TokenData]


class AuthRequest(BaseModel):
    login: constr(min_length=3, strip_whitespace=True) = Field(
        ..., description="The login of the user"
    )
    password: constr(min_length=8, strip_whitespace=True) = Field(
        ..., description="The plaintext password of the user"
    )
    device_fingerprint: str = Field(
        ..., description="The fingerprint of the user's device")


class UserBaseSchema(BaseModel):
    login: constr(min_length=3, strip_whitespace=True)
    first_name: str | None = Field(default=None, description="The first name of the user")
    last_name: str = Field(default="system", description="The last name of the user")
    is_admin: bool = Field(default=False, description="Boolean indicating if the user is a system superuser.")
    source: str = Field(default="manual", description="The source of the user (manual/yandex)")
    oa_id: str | None = Field(default=None, description="The OAuth ID.")


class UserCreateSchema(UserBaseSchema):
    password: (constr(min_length=8, strip_whitespace=True)
               | None) = Field(default=None, description="The plaintext password provided by the user or None.")


class OAuthUserCreateSchema(UserCreateSchema):
    @model_validator(mode='before')
    def set_composite_login(values):
        """
        Set a composite login if it's missing or empty.

        This method generates a composite login from the source and oa_id
        if the login field is not present or is empty.

        Args:
            values (dict): The values received for model fields.

        Returns:
            dict: The updated values with a composite login set, if necessary.
        """
        if 'login' not in values or not values['login']:
            values['login'] = f"{values.get('source')}:{values.get('oa_id')}"
        return values


class UserCreateInputSchema(UserCreateSchema):

    @model_validator(mode='before')
    def set_first_name(values):
        """
        Set the first name to be the same as the login if it's missing.
        This can be particularly useful for system users such as 'admin' or 'root',
        where using the login as the first name makes sense.


        This method checks if the 'first_name' field is present and not empty.
        If 'first_name' is missing or empty, it sets 'first_name' to the value of 'login'.

        Args:
            values (dict): The values received for model fields.

        Returns:
              dict: The updated values with 'first_name' set, if necessary.
        """
        if not values.get('first_name'):
            values['first_name'] = values.get('login')
        return values

    @model_validator(mode='before')
    def no_colon_in_login(values):
        """
        Ensure that the login field does not contain a colon (':') character.

        This method checks the 'login' field and raises a ValueError if the login
        contains a colon character. This is to enforce that logins do not contain
        colons, which might be reserved for other uses. Preventing colons in logins
        also helps avoid conflicts with logins structured similarly to OAuth users.

        Args:
            values (dict): The values received for model fields.

        Raises:
            ValueError: If the 'login' field contains a colon character.

        Returns:
            dict: The original values if validation passes.
        """

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
