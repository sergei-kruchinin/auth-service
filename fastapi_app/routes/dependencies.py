# fastapi_app > routes > dependencies.py

from fastapi import Depends, HTTPException, Header
from fastapi.security import OAuth2PasswordBearer
from typing import Annotated
import os
import logging
from redis import Redis

from core.services.token_service import TokenVerifier, TokenStorage
from core.services import get_db
from core.schemas import AuthorizationHeaders
from core.exceptions import *


logger = logging.getLogger(__name__)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token/form")


def get_redis_client() -> Redis:
    return Redis(host=os.getenv('REDIS_HOST', 'localhost'), port=int(os.getenv('REDIS_PORT', 6379)), db=0)


def get_token_verifier(redis_client: Redis = Depends(get_redis_client)) -> TokenVerifier:
    return TokenVerifier(redis_client)


def get_token_storage(redis_client: Redis = Depends(get_redis_client)) -> TokenStorage:
    return TokenStorage(redis_client)


def get_db_session():
    db = next(get_db())
    try:
        yield db
    finally:
        db.close()


async def token_required(authorization: Annotated[AuthorizationHeaders, Header()],
                         token: str = Depends(oauth2_scheme),
                         token_verifier: TokenVerifier = Depends(get_token_verifier)):
    """Dependency to verify the presence and validity of a Bearer token in the request headers."""
    logger.info("TOKEN_REQUIRED called")

    # token = authorization.token() # I like this method more than use OAuth2PasswordBearer but now...

    try:
        verification = token_verifier.verify_token(authorization.to_token_fingerprinted(token))
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
