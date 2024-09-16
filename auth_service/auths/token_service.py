# auths > token_service.py

import jwt
import os
from datetime import datetime, timezone, timedelta
import logging

import redis

from .schemas import AuthPayload, AuthResponse
from .exceptions import TokenBlacklisted, TokenExpired, TokenInvalid, DatabaseError
from redis import Redis, RedisError

AUTH_SECRET = os.getenv('AUTH_SECRET')
EXPIRES_SECONDS = int(os.getenv('EXPIRES_SECONDS'))
REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))

logger = logging.getLogger(__name__)

r = Redis(host=REDIS_HOST, port=REDIS_PORT, db=0)


class TokenService:
    """
    TokenService handles all operations related to JWT token generation, validation,
    and management of tokens in the blacklist.
    """

    @staticmethod
    def generate_token(payload: AuthPayload) -> AuthResponse:
        """
        Generate a JWT token and set its expiration time.

        Args:
            payload (AuthPayload): The payload data for the token.

        Returns:
            AuthResponse: The generated token and expiration time.
        """
        payload.exp = datetime.now(timezone.utc) + timedelta(seconds=EXPIRES_SECONDS)
        encoded_jwt = jwt.encode(payload.dict(), AUTH_SECRET, algorithm='HS256')
        logger.info("Generated new token")
        return AuthResponse(token=encoded_jwt, expires_in=EXPIRES_SECONDS)

    @staticmethod
    def add_to_blacklist(token: str):
        """
        Add a token to the blacklist.

        Args:
            token (str): The JWT token to be added to the blacklist.
        """
        logger.info(f"Adding token to blacklist: {token}")

        try:
            r.set(token, 'revoked')
            logger.info(f"Token added to blacklist: {token}")
        except RedisError as e:
            logger.error(f"Error adding token to blacklist: {str(e)}")
            raise DatabaseError(f"Error adding token to blacklist: {str(e)}") from e

    @staticmethod
    def is_blacklisted(token: str) -> bool:
        """
        Check if a token is in the blacklist.

        Args:
            token (str): The JWT token to be checked.

        Returns:
            bool: True if the token is blacklisted, False otherwise.
        """
        try:
            result = r.exists(token)
            logger.info(f"Checked blacklist status for token: {token}, Result: {result}")
            return result == 1
        except redis.RedisError as e:
            logger.error(f"Error checking if token is blacklisted: {str(e)}")
            raise DatabaseError(f"Error checking if token is blacklisted: {str(e)}") from e

    @staticmethod
    def verify_token(token: str) -> AuthPayload:
        """
        Verify a JWT token, ensuring it is not expired or blacklisted.

        Args:
            token (str): The JWT token to be verified.

        Returns:
            AuthPayload: The decoded payload of the token if valid.

        Raises:
            TokenBlacklisted: If the token is blacklisted.
            TokenExpired: If the token has expired.
            TokenInvalid: If the token is invalid.
        """
        logger.info(f"Verifying token: {token}")
        if TokenService.is_blacklisted(token):
            raise TokenBlacklisted("Token invalidated. Get new one")
        try:
            decoded = jwt.decode(token, AUTH_SECRET, algorithms=['HS256'])
            logger.info("Token successfully verified")
            return AuthPayload(**decoded)
        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            raise TokenExpired("Token expired. Get new one")
        except jwt.InvalidTokenError:
            logger.error("Invalid token")
            raise TokenInvalid("Invalid token")

