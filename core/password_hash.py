# core > password_hash.py

from passlib.context import CryptContext
import logging
logger = logging.getLogger(__name__)


class PasswordHash:
    pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

    # ### 1. Password Handling Methods ###

    @classmethod
    def generate(cls, password: str) -> str:
        """
        Generate a salted hash from plaintext password.

        Args:
            password (str): The plaintext password.

        Returns:
            str: The hashed password.
        """
        logger.info(f"Generating password hash {password}")
        try:
            return cls.pwd_context.hash(password)
        except AttributeError as e:
            logger.error(f"Password should be a string, got None: {str(e)}")
            raise TypeError("Password should be a string") from e

    @classmethod
    def check(cls, hashed_password: str, plain_password: str) -> bool:
        """
        Verify if the provided plaintext password matches the hashed password.

        Args:
            hashed_password (str): The hashed password stored in the database.
            plain_password (str): The plaintext password provided by the user.

        Returns:
            bool: True if the passwords match, False otherwise.
        """
        logger.info("Checking password hash")
        return cls.pwd_context.verify(plain_password, hashed_password)

