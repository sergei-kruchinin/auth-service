# core > exceptions.py

# Models Exception Classes
class AuthenticationError(Exception):
    pass


class TokenError(AuthenticationError):
    pass


class TokenBlacklisted(TokenError):
    pass


class TokenExpired(TokenError):
    pass


class TokenInvalid(TokenError):
    pass


class DatabaseError(Exception):
    pass


class DatabaseException(Exception):
    pass


class UserAlreadyExistsError(Exception):
    pass


# Routes Exceptions Class


class CustomValidationError(Exception):
    pass


class HeaderNotSpecifiedError(CustomValidationError):
    pass


class AdminRequiredError(Exception):
    pass


class NoDataProvided(Exception):
    """Raised when there is no input data provided."""
    pass


class ValidationErrorInherited(AuthenticationError):
    """Raised when there is insufficient data (username or password missing)."""

    def __init__(self, errors):
        """To get errors from ValidationError"""
        super().__init__(str(errors))
        self.errors = errors

class InsufficientAuthData(ValidationErrorInherited):
    """Raised when there is insufficient data (username or password missing)."""
    pass


class OAuthServerError(Exception):
    pass


class InvalidOauthGetParams(Exception):
    pass


class InvalidOauthPostJson(ValidationErrorInherited):
    pass

class OAuthTokenRetrievalError(OAuthServerError):
    pass


class OAuthUserDataRetrievalError(OAuthServerError):
    pass

