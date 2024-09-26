# core > schemas_exceptions.py

from .schemas import SimpleErrorResponseStatus


# === Exception Schemas For FastAPI and docs ===

class ResponseAuthenticationError(SimpleErrorResponseStatus):
    message: str = 'Invalid login or password'


class InsufficientAuthDataError(SimpleErrorResponseStatus):
    message: str = 'No login or password specified'
