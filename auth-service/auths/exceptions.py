
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


class InsufficientData(AuthenticationError):
    """Raised when there is insufficient data (login or password missing)."""
    pass


class OAuthServerError(Exception):
    pass


class OAuthTokenRetrievalError(OAuthServerError):
    pass


class OAuthUserDataRetrievalError(OAuthServerError):
    pass
