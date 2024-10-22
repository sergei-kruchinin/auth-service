# flask_app > routes > dependencies.py

from functools import wraps
from flask import request
import logging
import os
from contextlib import contextmanager
from core.token_service import TokenService
from core.models import get_db
from core.exceptions import *
from core.schemas import AuthorizationHeaders, RawFingerPrint

logger = logging.getLogger(__name__)


@contextmanager
def get_db_session():
    db = next(get_db())
    try:
        yield db
    finally:
        db.close()


def with_db(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        with get_db_session() as db:
            return f(*args, **kwargs, db=db)
    return decorated


def fingerprint_required(f):
    """
    Generates a device fingerprint based on the User-Agent and Accept-Language headers.

    This function extracts the User-Agent and Accept-Language headers from
    the incoming HTTP request and combines them to create a unique fingerprint
    for the device. Then running function f with device_fingerprint.

    Args:
        f (function): The function to be decorated.

    Returns:
        function: The wrapped function with device_fingerprint parameter added.
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        user_agent = request.headers.get('user_agent')
        accept_language = request.headers.get('accept_language')
        x_forwarded_header = request.headers.get("X-Forwarded-For")
        x_real_ip = request.headers.get("X-Real-IP")
        host = request.remote_addr
        device_fingerprint = RawFingerPrint(
                                       user_agent=user_agent,
                                       accept_language=accept_language,
                                       x_forwarded_header=x_forwarded_header,
                                       x_real_ip=x_real_ip,
                                       host=host
                                       )
        return f(device_fingerprint=device_fingerprint, *args, **kwargs)

    return decorated


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
        authorization_header = request.headers.get('authorization')
        user_agent = request.headers.get('user_agent')
        accept_language = request.headers.get('accept_language')
        authorization = AuthorizationHeaders(
                                             user_agent=user_agent,
                                             accept_language=accept_language,
                                             authorization=authorization_header)
        try:
            verification = TokenService.verify_token(authorization.to_token_fingerprinted())
        except TokenBlacklisted as e:
            logger.warning(f"Token invalidated. Get new one: {str(e)}")
            raise TokenBlacklisted("Token invalidated. Get new one") from e
        except TokenExpired as e:
            logger.warning(f"Token expired. Get new one: {str(e)}")
            raise TokenExpired("Token expired. Get new one") from e
        except TokenInvalid as e:
            logger.error(f"Invalid token: {str(e)}")
            raise TokenInvalid("Invalid token") from e

        return f(verification=verification, *args, **kwargs)

    return decorated


def get_yandex_uri():
    yandex_id = os.getenv('YANDEX_ID')
    iframe_uri = f'https://oauth.yandex.ru/authorize?response_type=code&client_id={yandex_id}'
    return iframe_uri
