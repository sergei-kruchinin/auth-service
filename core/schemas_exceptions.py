# core > schemas_exceptions.py


from pydantic import BaseModel
from typing import Dict, Any, List

from .schemas import SimpleErrorResponseStatus


# === Exception Schemas For FastAPI and docs ===


class ErrorDetail(BaseModel):
    detail: List[Dict[str, Any]] | None


class ResponseAuthenticationError(SimpleErrorResponseStatus):
    message: str = 'Invalid username or password'


class InsufficientAuthDataError(SimpleErrorResponseStatus, ErrorDetail):
    message: str = 'No username or password specified'


class OAuthServerErrorSchema(SimpleErrorResponseStatus):
    message: str = 'OAuth Server Error'


class InvalidOauthGetParamsSchema(SimpleErrorResponseStatus):
    message: str = 'OAuth Token or authorization code is missing'


class InvalidOauthPostJsonSchema(SimpleErrorResponseStatus, ErrorDetail):
    message: str = 'OAuth Token is missing'


class TokenInvalidErrorSchema(SimpleErrorResponseStatus):
    message: str = 'Token Invalid or Expired'
