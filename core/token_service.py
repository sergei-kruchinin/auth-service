# core > token_service.py

import jwt
import os
from datetime import datetime, timezone, timedelta
import logging
import redis

from .schemas import TokenPayload, TokenData, TokenVerification
from .exceptions import TokenBlacklisted, TokenExpired, TokenInvalid, DatabaseError
from redis import Redis, RedisError
from enum import Enum

AUTH_SECRET = os.getenv('AUTH_SECRET')
# Set 60 to see deleting invalidated token from redis when ttl will be expired
ACCESS_EXPIRES_SECONDS = int(os.getenv('ACCESS_EXPIRES_SECONDS', 600))  # 10 minutes
REFRESH_EXPIRES_SECONDS = int(os.getenv('REFRESH_EXPIRES_SECONDS', 1209600))  # 14 days
REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))

logger = logging.getLogger(__name__)

r = Redis(host=REDIS_HOST, port=REDIS_PORT, db=0)


class TokenType(Enum):
    """
    TokenType defines the types of tokens that can be generated.

    Attributes:
        ACCESS (str): Represents an access token.
        REFRESH (str): Represents a refresh token.
    """
    ACCESS = 'access'
    REFRESH = 'refresh'


class TokenService:
    """
    TokenService handles all operations related to JWT token generation, validation,
    and management of tokens in the blacklist.
    """

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
        if token_type == TokenType.ACCESS:
            expires_in = ACCESS_EXPIRES_SECONDS
        elif token_type == TokenType.REFRESH:
            expires_in = REFRESH_EXPIRES_SECONDS
        else:
            raise ValueError("Invalid token type")

        exp = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
        jwt_payload = payload.dict().copy()
        jwt_payload.update({"exp": exp.timestamp()})

        encoded_jwt = jwt.encode(jwt_payload, AUTH_SECRET, algorithm='HS256')
        logger.info(f"Generated new {token_type.value} token")
        return TokenData(value=encoded_jwt, expires_in=expires_in)

    @staticmethod
    def get_token_ttl(token: str) -> int:
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
            # If the token has expired, the TTL will be negative. In this case, it will return 0.
            # Otherwise, it will return the actual time-to-live.
            return max(0, int(ttl))
        except jwt.DecodeError:
            raise TokenInvalid("Invalid token")

    @staticmethod
    def add_to_blacklist(token: str):
        """
        Add a token to the blacklist.

        Args:
            token (str): The JWT token to be added to the blacklist.
        """
        logger.info(f"Adding token to blacklist: {token}")

        try:
            ttl = TokenService.get_token_ttl(token)
            r.setex(token, ttl, 'revoked')
            logger.info(f"Token added to blacklist: {token}")
        except RedisError as e:
            logger.error(f"Error adding token to blacklist: {str(e)}")
            raise DatabaseError(f"Error adding token to blacklist: {str(e)}") from e
        except TokenInvalid:
            raise

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
    def verify_token(token: str, device_fingerprint: str) -> TokenVerification:
        """
        Verify a JWT token, ensuring it is not expired or blacklisted.

        This method decodes the JWT token, checks if it is blacklisted, verifies
        the expiration time, and ensures that the token was issued to the device
        with the specified fingerprint.

        Args:
            token (str): The JWT token to be verified.
            device_fingerprint (str): The fingerprint of the device attempting to use
                                      the token. This is used to ensure the token is
                                      being used on the same device it was issued to.

        Returns:
            TokenVerification: The token and expiration with decoded payload of the token if valid, containing user data
                               and additional claims.

        Raises:
            TokenBlacklisted: If the token is blacklisted.
            TokenExpired: If the token has expired.
            TokenInvalid: If the token is invalid or if the device fingerprint does not match.
        """

        logger.info(f"Verifying token: {token}")
        if TokenService.is_blacklisted(token):
            raise TokenBlacklisted("Token invalidated. Get new one")
        try:
            decoded = jwt.decode(token, AUTH_SECRET, algorithms=['HS256'])
            token_payload = TokenPayload(**decoded)
            if token_payload.device_fingerprint != device_fingerprint:
                logger.warning("Device fingerprint does not match")
                raise TokenInvalid("Device fingerprint does not match")
            logger.info("Token successfully verified")
            token_verification = TokenVerification(access_token=token, **token_payload.dict())
            return token_verification
        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            raise TokenExpired("Token expired. Get new one")
        except jwt.InvalidTokenError:
            logger.error("Invalid token")
            raise TokenInvalid("Invalid token")
