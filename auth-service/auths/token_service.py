import jwt
import os
from datetime import datetime, timezone, timedelta
import logging
from .schemas import AuthPayload, AuthResponse
from . import db
from .exceptions import TokenBlacklisted, TokenExpired, TokenInvalid, DatabaseError

AUTH_SECRET = os.getenv('AUTH_SECRET')
EXPIRES_SECONDS = int(os.getenv('EXPIRES_SECONDS'))
logger = logging.getLogger(__name__)


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
        TokenService.Blacklist.add_token(token)

    @staticmethod
    def is_blacklisted(token: str) -> bool:
        """
        Check if a token is in the blacklist.

        Args:
            token (str): The JWT token to be checked.

        Returns:
            bool: True if the token is blacklisted, False otherwise.
        """
        result = TokenService.Blacklist.is_blacklisted(token)
        logger.info(f"Token blacklisted: {result}")
        return result

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
            logger.error("Token expired")
            raise TokenExpired("Token expired. Get new one")
        except jwt.InvalidTokenError:
            logger.error("Invalid token")
            raise TokenInvalid("Invalid token")

    class Blacklist(db.Model):
        """
        Inner class for managing the blacklist of tokens.
        """
        token = db.Column(db.String(256), primary_key=True, nullable=False)

        @classmethod
        def add_token(cls, black_token: str):
            """
            Add a token to the blacklist.

            Args:
                black_token (str): The JWT token to be blacklisted.
            """
            try:
                black_token_record = cls(token=black_token)
                db.session.add(black_token_record)
                db.session.commit()
                logger.info(f"Token added to blacklist: {black_token}")
            except Exception as e:
                db.session.rollback()
                logger.error(f"Error adding token to blacklist: {str(e)}")
                raise DatabaseError(f"Error adding token to blacklist: {str(e)}") from e

        @classmethod
        def is_blacklisted(cls, token: str) -> bool:
            """
            Check if a token is in the blacklist.

            Args:
                token (str): The JWT token to be checked.

            Returns:
                bool: True if the token is blacklisted, False otherwise.
            """
            try:
                result = bool(cls.query.get(token))
                logger.info(f"Checked blacklist status for token: {token}, Result: {result}")
                return result
            except Exception as e:
                logger.error(f"Error checking if token is blacklisted: {str(e)}")
                raise DatabaseError(f"Error checking if token is blacklisted: {str(e)}") from e

        def __repr__(self):
            return f'In blacklist: {self.token}'
