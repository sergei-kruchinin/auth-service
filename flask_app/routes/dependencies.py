# core > routes > dependencies.py

from functools import wraps
from flask import request
import logging
from core.token_service import TokenService
from core.exceptions import *
import os
logger = logging.getLogger(__name__)


def get_device_fingerprint() -> str:
    """Generates a device fingerprint based on the User-Agent and Accept-Language headers.

    This function extracts the User-Agent and Accept-Language headers from
    the incoming HTTP request and combines them to create a unique fingerprint
    for the device. If the User-Agent header is missing, a warning is logged.

    Returns:
        str: A string representing the device fingerprint, composed of
        the User-Agent and Accept-Language headers separated by a colon.
    """
    user_agent = request.headers.get('User-Agent')
    if not user_agent:
        logger.warning("User-Agent header is missing")
        user_agent = "unknown"

    accept_language = request.headers.get('Accept-Language', 'unknown')
    return f"{user_agent}:{accept_language}"


def token_required(f):
    """
    Decorator to verify the presence and validity of a Bearer token in the request headers.

    This decorator checks for an 'Authorization' header with the prefix 'Bearer '.
    If the token is valid, it passes the token and verification result to the decorated function.

    Args:
        f (function): The function to be decorated.

    Raises:
        HeaderNotSpecifiedError: If the authorization header is not specified or does not start with 'Bearer '.
        TokenBlacklisted: If the token has been invalidated.
        TokenExpired: If the token has expired.
        TokenInvalid: If the token is invalid.

    Returns:
        function: The wrapped function with token and verification parameters added.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        device_fingerprint = get_device_fingerprint()
        authorization_header = request.headers.get('authorization')
        prefix = 'Bearer '
        if not authorization_header or not authorization_header.startswith(prefix):
            logger.error("Authorization header missing or does not start with 'Bearer '")
            raise HeaderNotSpecifiedError('Header not specified or prefix not supported.')

        token = authorization_header[len(prefix):]
        try:
            verification = TokenService.verify_token(token, device_fingerprint).dict()
        except TokenBlacklisted as e:
            logger.warning(f"Token invalidated. Get new one: {str(e)}")
            raise TokenBlacklisted("Token invalidated. Get new one") from e
        except TokenExpired as e:
            logger.warning(f"Token expired. Get new one: {str(e)}")
            raise TokenExpired("Token expired. Get new one") from e
        except TokenInvalid as e:
            logger.error(f"Invalid token: {str(e)}")
            raise TokenInvalid("Invalid token") from e

        return f(token, verification, *args, **kwargs)

    return decorated


def get_yandex_uri():
    yandex_id = os.getenv('YANDEX_ID')
    iframe_uri = f'https://oauth.yandex.ru/authorize?response_type=code&client_id={yandex_id}'
    return iframe_uri

