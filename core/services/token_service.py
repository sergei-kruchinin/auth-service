# core > services > token_service
import jwt
import os
from datetime import datetime, timezone, timedelta
import logging
from redis import RedisError
from enum import Enum
from typing import Protocol

from core.schemas import TokenPayload, TokenData, TokenVerification, TokenFingerPrinted
from core.exceptions import TokenBlacklisted, TokenExpired, TokenInvalid, DatabaseError

# Load configuration from environment variables
AUTH_SECRET = os.getenv('AUTH_SECRET')
ACCESS_EXPIRES_SECONDS = int(os.getenv('ACCESS_EXPIRES_SECONDS', 600))  # 10 minutes
REFRESH_EXPIRES_SECONDS = int(os.getenv('REFRESH_EXPIRES_SECONDS', 1209600))  # 14 days

# Setup logger
logger = logging.getLogger(__name__)


# Protocol for Redis interface
class RedisClientProtocol(Protocol):
    def setex(self, name: str, time: int, value: str) -> None:
        ...

    def exists(self, name: str) -> int:
        ...


class TokenType(Enum):
    """
    TokenType defines the types of tokens that can be generated.

    Attributes:
        ACCESS (str): Represents an access token.
        REFRESH (str): Represents a refresh token.
    """

    ACCESS = 'access'
    REFRESH = 'refresh'


class TokenGenerator:
    """Class for JWT-token generation"""

    @staticmethod
    def generate_token(payload: TokenPayload, token_type: TokenType) -> TokenData:
        """
        Generate a JWT token of the specified type and set its expiration time.
        Args:
            payload (TokenPayload): The payload data for the token.
            token_type (TokenType): The type of token to generate (TokenType.ACCESS or TokenType.REFRESH).
        Returns:
            TokenData: The generated token and expiration time.
        """
        if not isinstance(AUTH_SECRET, str):
            raise TypeError("AUTH_SECRET must be a string")

        expires_in = ACCESS_EXPIRES_SECONDS if token_type == TokenType.ACCESS else REFRESH_EXPIRES_SECONDS
        exp = datetime.now(timezone.utc) + timedelta(seconds=expires_in)

        jwt_payload = payload.dict().copy()
        jwt_payload.update({"exp": exp.timestamp()})

        encoded_jwt = jwt.encode(jwt_payload, AUTH_SECRET, algorithm='HS256')
        logger.info(f"Generated new {token_type.value} token")
        return TokenData(value=encoded_jwt, expires_in=expires_in)


class TokenVerifier:
    """ Class for verifying tokens"""
    def __init__(self, redis_client: RedisClientProtocol):
        self.token_storage = TokenStorage(redis_client)

    def verify_token(self, token: TokenFingerPrinted) -> TokenVerification:
        """
        Verify a JWT token
        Args:
            token (TokenFingerPrinted): the JWT token with fingerprint
        Returns:
            TokenVerification: the verified token info
        """
        logger.info(f"Verifying token: {token.value}")
        if self.token_storage.is_blacklisted(token.value):
            raise TokenBlacklisted("Token invalidated. Get new one")
        try:
            decoded = jwt.decode(token.value, AUTH_SECRET, algorithms=['HS256'])
            token_payload = TokenPayload(**decoded)
            if token_payload.device_fingerprint != token.device_fingerprint:
                logger.warning("Device fingerprint does not match")
                raise TokenInvalid("Device fingerprint does not match")
            logger.info("Token successfully verified")
            return token_payload.to_response(access_token=token.value)
        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            raise TokenExpired("Token expired. Get new one")
        except jwt.InvalidTokenError:
            logger.error("Invalid token")
            raise TokenInvalid("Invalid token")


# Class for managing token storage and blacklisting
class TokenStorage:
    def __init__(self, redis_client: RedisClientProtocol):
        self.redis_client = redis_client

    def add_to_blacklist(self, token: str):
        """
        Add token to the blacklist

        Args:
            token (str): The JWT token to be blacklisted
        """
        logger.info(f"Adding token to blacklist: {token}")
        try:
            ttl = self.get_token_ttl(token)
            self.redis_client.setex(token, ttl, 'revoked')
            logger.info(f"Token added to blacklist: {token}")
        except RedisError as e:
            logger.error(f"Error adding token to blacklist: {str(e)}")
            raise DatabaseError(f"Error adding token to blacklist: {str(e)}") from e
        except TokenInvalid:
            raise

    def is_blacklisted(self, token: str) -> bool:
        """
        Check if the token is blacklisted

        Args:
            token (str): The JWT token.

        Returns:
            bool: True if the token is blacklisted else False.
        """
        try:
            result = self.redis_client.exists(token)
            logger.info(f"Checked blacklist status for token: {token}, Result: {result}")
            return result == 1
        except RedisError as e:
            logger.error(f"Error checking if token is blacklisted: {str(e)}")
            raise DatabaseError(f"Error checking if token is blacklisted: {str(e)}") from e

    def get_token_ttl(self, token: str) -> int:
        """
        Calculate the remaining time-to-live (TTL) for a JWT token.

        Args:
            token (str): The JWT token.

        Returns:
            int: The remaining TTL in seconds.
        """

        try:
            decoded = jwt.decode(token, AUTH_SECRET, algorithms=['HS256'], options={"verify_signature": False})
            exp = decoded.get('exp')
            if not exp:
                raise TokenInvalid("Token does not contain 'exp' claim")

            current_time = datetime.now(timezone.utc).timestamp()
            ttl = exp - current_time
            return max(0, int(ttl))
        except jwt.DecodeError:
            raise TokenInvalid("Invalid token")



