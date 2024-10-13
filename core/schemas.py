# core > schemas.py
# Pydantic models

from datetime import datetime
from pydantic import BaseModel, Field, constr, model_validator, ConfigDict
from typing import Dict, Any, List


# === Response Models

class ResponseBase(BaseModel):
    success: bool | None = Field(default=None, description="Response Status: True of False. None is error")


class SimpleResponseStatus(ResponseBase):
    message: str = Field(..., description="Status description")


class SimpleErrorResponseStatus(ResponseBase):
    success: bool = False


class SimpleSuccessResponseStatus(ResponseBase):
    success: bool = True


class IframeUrlResponse(SimpleSuccessResponseStatus):
    iframe_url: str = Field(..., description="Iframe URL for OAuth")





# === Token Models ===
class TokenPayload(BaseModel):
    id: int = Field(..., description="User id in our database")
    username: str = Field(..., description="Username of user, incl. composite Username <oa:id>")
    first_name: str = Field(..., description="The first name of user, for system users can be == username")
    last_name: str = Field(..., description="The first name of user, for system users can be 'system'")
    is_admin: bool = Field(default=False, description="Boolean indicating if the user is a system superuser.")
    device_fingerprint: str = Field(default=None, description="Device/browser fingerprint: <useragent:lang>")
    exp: datetime = Field(default=None, description="The value will be set by token generation")

    def to_response(self, access_token: str) -> 'TokenVerification':
        return TokenVerification(
            id=self.id,
            username=self.username,
            first_name=self.first_name,
            last_name=self.last_name,
            is_admin=self.is_admin,
            device_fingerprint=self.device_fingerprint,
            exp=self.exp.isoformat(),
            access_token=access_token,
            success=True
        )


class TokenValue(BaseModel):
    value: constr(min_length=95) = Field(..., description="JWT токен")


class AccessTokenResponseValue(BaseModel):
    access_token: constr(min_length=95) = Field(..., description="JWT токен")


class TokenData(TokenValue):
    expires_in: int

    def to_response(self) -> 'TokenDataResponse':
        """
        Converts TokenData to TokenDataResponse.
        """
        return TokenDataResponse(
            access_token=self.value,
            expires_in=self.expires_in,
        )


class TokenDataResponse(AccessTokenResponseValue, SimpleSuccessResponseStatus):
    expires_in: int


class TokenVerification(TokenPayload, AccessTokenResponseValue, ResponseBase):
    exp: str


class AuthTokens(BaseModel):
    tokens: Dict[str, TokenData]


class AuthRequest(BaseModel):
    username: constr(min_length=3, strip_whitespace=True) = Field(
        ..., description="The username of the user"
    )
    password: constr(min_length=8, strip_whitespace=True) = Field(
        ..., description="The plaintext password of the user"
    )

    def to_fingerprinted(self, fingerprint: str) -> 'AuthRequestFingerPrinted':
        return AuthRequestFingerPrinted(
            username=self.username,
            password=self.password,
            device_fingerprint=fingerprint)


class AuthRequestFingerPrinted(AuthRequest):
    username: constr(min_length=3, strip_whitespace=True) = Field(
        ..., description="The username of the user"
    )
    password: constr(min_length=8, strip_whitespace=True) = Field(
        ..., description="The plaintext password of the user"
    )
    device_fingerprint: str = Field(
        ..., description="The fingerprint of the user's device")

# === User Models ===


class UserBaseSchema(BaseModel):
    username: constr(min_length=3, strip_whitespace=True)
    first_name: str | None = Field(default=None, description="The first name of the user")
    last_name: str = Field(default="system", description="The last name of the user")
    is_admin: bool = Field(default=False, description="Boolean indicating if the user is a system superuser.")
    source: str | None = Field(default=None, description="The source of the user (manual/yandex)")
    oa_id: str | None = Field(default=None, description="The OAuth ID.")


class UserCreateSchema(UserBaseSchema):
    password: (constr(min_length=8, strip_whitespace=True)
               | None) = Field(default=None, description="The plaintext password provided by the user or None.")

    def to_user_create_schema(self) -> 'UserCreateSchema':
        return UserCreateSchema(
            username=self.username,
            first_name=self.first_name,
            last_name=self.last_name,
            is_admin=self.is_admin,
            source=self.source,
            oa_id=self.oa_id,
            password=self.password
        )


# === OAuth User Create Schema ===


class OAuthUserCreateSchema(UserCreateSchema):

    @model_validator(mode='before')
    def set_composite_username(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        """
        Set a composite username if it's missing or empty.

        This method generates a composite username from the source and oa_id
        if the username field is not present or is empty.

        Args:
            values (dict): The values received for model fields.

        Returns:
            dict: The updated values with a composite username set, if necessary.
        """
        if 'username' not in values or not values['username']:
            values['username'] = f"{values.get('source')}:{values.get('oa_id')}"
        return values


# === Manual User Create Schema ===

class ManualUserCreateSchema(UserCreateSchema):

    @model_validator(mode='before')
    def set_first_name(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        """
        Set the first name to be the same as the username if it's missing.
        This can be particularly useful for system users such as 'admin' or 'root',
        where using the username as the first name makes sense.


        This method checks if the 'first_name' field is present and not empty.
        If 'first_name' is missing or empty, it sets 'first_name' to the value of 'username'.

        Args:
            values (dict): The values received for model fields.

        Returns:
              dict: The updated values with 'first_name' set, if necessary.
        """
        if not values.get('first_name'):
            values['first_name'] = values.get('username')
        return values

    @model_validator(mode='before')
    def set_source_for_manual_user(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        """
        Set the source as 'manual' for manual users


        This method does not check 'source' fields are present,
        because it should not present in input for manual users.
        If it is filled it will override.

        Args:
            values (dict): The values received for model fields.

        Returns:
              dict: The updated values with source set as 'manual'.
        """

        values['oa_id'] = values.get('id')
        values['source'] = 'manual'
        return values

    @model_validator(mode='before')
    def no_colon_in_username(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ensure that the username field does not contain a colon (':') character.

        This method checks the 'username' field and raises a ValueError if the username
        contains a colon character. This is to enforce that usernames do not contain
        colons, which might be reserved for other uses. Preventing colons in usernames
        also helps avoid conflicts with usernames structured similarly to OAuth users.

        Args:
            values (dict): The values received for model fields.

        Raises:
            ValueError: If the 'username' field contains a colon character.

        Returns:
            dict: The original values if validation passes.
        """

        username = values.get('username')
        if username and ':' in username:
            raise ValueError("Username must not contain the ':' character")
        return values


# === User Response Schema ===

class UserResponseSchema(UserBaseSchema):
    id: int
    # created_at: str
    # updated_at: str | None = None
    model_config = ConfigDict(from_attributes=True)


class UsersResponseSchema(SimpleSuccessResponseStatus):
    users: List[UserResponseSchema]


# === Yandex User Info ===

class YandexUserInfo(BaseModel):
    id: str
    first_name: str
    last_name: str


# === User Session Data ===

class UserSessionData(BaseModel):
    user_id: int
    ip_address: str
    user_agent: str
    accept_language: str
    refresh_token: str
    expires_at: datetime
