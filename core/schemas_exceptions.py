# core > schemas_exceptions.py

from .schemas import SimpleErrorResponseStatus


# === Exception Schemas For FastAPI and docs ===

class ResponseAuthenticationError(SimpleErrorResponseStatus):
    message: str = 'Invalid username or password'


class InsufficientAuthDataError(SimpleErrorResponseStatus):
    message: str = 'No username or password specified'


class OAuthServerErrorSchema(SimpleErrorResponseStatus):
    message: str = 'OAuth Server Error'


class TokenInvalidErrorSchema(SimpleErrorResponseStatus):
    message: str = 'Token Invalid or Expired'
