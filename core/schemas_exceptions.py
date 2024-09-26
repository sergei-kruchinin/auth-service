# core > schemas_exceptions.py

from .schemas import SimpleErrorResponseStatus


# === Exception Schemas ==

class ResponseAuthenticationError(SimpleErrorResponseStatus):
    message: str = 'Invalid login or password'
