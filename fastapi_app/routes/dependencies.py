# fastapi_app > routes > dependencies.py

from fastapi import Depends, HTTPException, Request, Header
from fastapi.security import OAuth2PasswordBearer
from core.token_service import TokenService
from typing import Annotated
import os
import logging
from core.models import get_db
from core.schemas import RawFingerPrint, AuthorizationHeaders
from core.exceptions import *


logger = logging.getLogger(__name__)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token/form")


def get_db_session():
    db = next(get_db())
    try:
        yield db
    finally:
        db.close()


async def token_required(authorization: Annotated[AuthorizationHeaders, Header()],
                         _: oauth2_scheme = Depends(oauth2_scheme)):
    """Dependency to verify the presence and validity of a Bearer token in the request headers."""
    logger.info("TOKEN_REQUIRED called")
    token = authorization.token()

    try:
        verification = TokenService.verify_token(token, authorization.to_fingerprint())
        return verification
    except TokenBlacklisted as e:
        logger.warning(f"Token invalidated. Get new one: {str(e)}")
        raise HTTPException(status_code=401, detail="Token invalidated. Get new one") from e
    except TokenExpired as e:
        logger.warning(f"Token expired. Get new one: {str(e)}")
        raise HTTPException(status_code=401, detail="Token expired. Get new one") from e
    except TokenInvalid as e:
        logger.error(f"Invalid token: {str(e)}")
        raise HTTPException(status_code=401, detail="Invalid token") from e


def get_yandex_uri() -> str:
    yandex_id = os.getenv('YANDEX_ID')
    iframe_uri = f'https://oauth.yandex.ru/authorize?response_type=code&client_id={yandex_id}'
    return iframe_uri
