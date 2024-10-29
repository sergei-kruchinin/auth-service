# core > services > user.py

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from typing import Dict, Optional, Protocol
import logging

from core.schemas import *
from core.exceptions import AuthenticationError, UserAlreadyExistsError, DatabaseError
from core.services.token_service import TokenType, TokenGenerator
from core.services.user_session import UserSession
from core.models.user import UserTable
logger = logging.getLogger(__name__)


class PasswordHashProtocol(Protocol):
    """Protocol for PasswordHash interface"""
    @classmethod
    def generate(cls, password: str) -> str:
        """
        Generate a salted hash from plaintext password.
        """
        ...

    @classmethod
    def check(cls, hashed_password: str, plain_password: str) -> bool:
        """
        Verify if the provided plaintext password matches the hashed password.
        """
        ...


class User:
    """
    Represents a user in the application.
    Contains User Management Methods

    """
    user: UserTable

    def __init__(self, user_record: UserTable):
        self.user = user_record


    @classmethod
    def list(cls, db: Session) -> Dict[str, List[Dict]]:
        """
        Retrieve the list of all users.

        Returns:
            dict: A dictionary with a list of all users.

        Raises:
            DatabaseError: If there was an error while retrieving users.
        """
        try:
            users = db.query(UserTable).all()
            return {'users': [UserResponseSchema.from_orm(user).dict() for user in users]}
        except SQLAlchemyError as e:
            logger.error(f"There was an error while retrieving users: {str(e)}")
            raise DatabaseError(f"There was an error while retrieving users{str(e)}") from e

    @classmethod
    def _create(cls, db: Session, user_data: UserCreateSchema, password_hasher: PasswordHashProtocol | None) -> 'User':
        """
        Create a new user without checking if the user already exists.
        If user exists, raises a DatabaseError indicating user already exists.

        Args:
            db (Session): Session
            user_data (UserCreateSchema): The data to create a new user.
            password_hasher (PasswordHashProtocol): Provides methods for hash and check
                                                    None for OAuth users
        Returns:
            Users: The newly created user.

        Raises:
            DatabaseError: If there was an error while creating a user.
            UserAlreadyExistsError: If user with the username already exists.
          """
        logger.debug("Creating new user")
        try:

            secret = None
            if password_hasher and user_data.password is not None:
                secret = password_hasher.generate(user_data.password)

            # new_user = UserTable(**user_data.dict())
            new_user = UserTable(username=user_data.username,
                                 first_name=user_data.first_name,
                                 last_name=user_data.last_name,
                                 secret=secret,
                                 is_admin=bool(user_data.is_admin),
                                 source=user_data.source,
                                 oa_id=user_data.oa_id)
            db.add(new_user)
            db.commit()

            # Set the `oa_id` for a manually created user.
            # This code cannot be moved to Schemas as method
            # because `id` in Schemas is not present and so cannot be filled.
            if new_user.source == 'manual' and new_user.oa_id is None:
                new_user.oa_id = str(new_user.id)
                db.commit()

            logger.info(f"User created successfully: {new_user.username}")
            return cls(new_user)
        except SQLAlchemyError as e:
            db.rollback()
            logger.error(f"There was an error while creating a user: {str(e)}")
            raise DatabaseError(f"There was an error while creating a user: {str(e)}") from e

    @classmethod
    def get_user_by_username(cls, db: Session, username: str) -> Optional['User']:
        """
        Fetch a user by username.

        This method is used for retrieving a user by their username.
        It can also be used for checking if a user exists in the database.

        Args:
            db (Session): The SQLAlchemy session to use for the database query.
            username (str): The username of the user to fetch.

        Returns:
            User: The user object if found, otherwise None.
        """
        logger.debug(f"Fetching user by username: {username}")
        try:
            user = db.query(UserTable).filter_by(username=username).first()
            return cls(user) if user else None
        except SQLAlchemyError as e:
            logger.error(f"There was an error while fetching the user: {str(e)}")
            raise DatabaseError(f"There was an error while fetching the user: {str(e)}") from e

    @classmethod
    def create_with_check(cls,
                          db: Session,
                          user_data: ManualUserCreateSchema,
                          password_hasher: PasswordHashProtocol) -> 'User':
        """
        Create a new user after checking if the user already exists.
        If user exists, raises a UserAlreadyExistsError indicating user already exists.

        Args:
            db (Session): Session
            user_data (dict): The data to create a new user.
            password_hasher (PasswordHashProtocol): Provides methods for hash and check

        Returns:
            Users: The newly created user.

        Raises:
            UserAlreadyExistsError: If user with the username already exists.
        """

        logger.debug("Creating new user with check")

        if cls.get_user_by_username(db, user_data.username) is not None:
            logger.warning(f"User with username {user_data.username} already exists")
            raise UserAlreadyExistsError(f"User with username {user_data.username} already exists")

        try:
            user_data = user_data.to_user_create_schema()
            user = cls._create(db, user_data, password_hasher)
            return user
        except DatabaseError as e:
            logger.error(f"Database error occurred: {str(e)}")
            raise
        except SQLAlchemyError as e:
            logger.error(f"There was an error while creating user: {str(e)}")
            raise DatabaseError(f"There was an error while creating user {str(e)}") from e

    def authenticator(self) -> 'Authenticator':
        return Authenticator(self.user)

    def secret(self) -> str:
        return self.user.secret

    def __repr__(self) -> str:
        return (f'<User(username={self.user.username}, id={self.user.id}, is_admin={self.user.is_admin})>'
                f'')


class Authenticator:
    """
    Class contains Authentication Methods
    """
    user: UserTable

    def __init__(self, user_record: UserTable):
        self.user = user_record

    def generate_auth_response_and_save_session(self,
                                                db: Session,
                                                device_fingerprint: FingerPrintedData) -> AuthTokens:
        """
        Generate authentication response including JWT token and its expiration time.

        Returns:
            Dict: The generated token and expiration time.
        """
        payload = TokenPayload(
            id=self.user.id,
            username=self.user.username,
            first_name=self.user.first_name,
            last_name=self.user.last_name,
            is_admin=self.user.is_admin,
            device_fingerprint=device_fingerprint.device_fingerprint
        )
        logger.info("Generating access and refresh token")
        tokens = {token_type.value: TokenGenerator.generate_token(payload, token_type) for token_type in TokenType}
        logger.info("Access and refresh token generates")

        session_data = UserSessionData(
            user_id=self.user.id,
            ip_address=device_fingerprint.ip,
            user_agent=device_fingerprint.user_agent,
            accept_language=device_fingerprint.accept_language,
            refresh_token=tokens[TokenType.REFRESH.value].value,
            expires_in=tokens[TokenType.REFRESH.value].expires_in)
        print('SESSION:', session_data)
        UserSession.create_session(db, session_data)

        return AuthTokens(tokens=tokens, user_id=self.user.id)

    @staticmethod
    def authenticate(db: Session,
                     auth_request: AuthRequestFingerPrinted,
                     password_hasher: PasswordHashProtocol) -> AuthTokens:
        """
        Authenticate user with username and password.

        Args:
            auth_request (AuthRequestFingerPrinted): The username and plaintext password of the user.
            db (Session): Session
            password_hasher (PasswordHashProtocol): Provides methods for hash and check
        Returns:
            AuthTokens: The generated access and refresh tokens and their expiration times.
        Raises:
            AuthenticationError: If username or password is invalid.
        """
        logger.debug(f"Authenticating user: {auth_request.username}")
        try:
            # user = db.query(UserTable).filter_by(username=auth_request.username).first()
            user = User.get_user_by_username(db, auth_request.username)

            if user is None or not password_hasher.check(str(user.secret()), auth_request.password):
                logger.warning(f"Authentication failed for user: {auth_request.username}")
                raise AuthenticationError('Invalid username or invalid password')
            logger.info(f"User authenticated successfully: {auth_request.username}")

            # authenticator = Authenticator(user)
            authenticator = user.authenticator()
            return authenticator.generate_auth_response_and_save_session(db, auth_request)

        except SQLAlchemyError as e:
            logger.error(f"There was an error accessing the database: {str(e)}")
            raise DatabaseError(f"There was an error accessing the database: {str(e)}") from e


class OAuthUser(User):
    def _update_oauth_user(self, db: Session, oauth_user_data: OAuthUserCreateSchema) -> None:
        """
        Update an existing OAuth user with new data.

        Args:
            db (Session): Session
            oauth_user_data (OAuthUserCreateSchema): New data for updating the user
        """
        self.user.first_name = oauth_user_data.first_name
        self.user.last_name = oauth_user_data.last_name
        self.user.is_admin = oauth_user_data.is_admin

        try:
            db.commit()
        except SQLAlchemyError as e:
            logger.error(f"There was an error while updating the user: {str(e)}")
            db.rollback()
            raise DatabaseError(str(e)) from e

    @classmethod
    def create_or_update_oauth_user(cls,
                                    db: Session,
                                    oauth_user_data: OAuthUserCreateSchema) -> 'User':
        """
        Create or update a user for OAuth 2.0 authorization.
        It always updates user data from OAuth Provider,
        if it is the first authorization -- create user data in the database.

        Args:
            db (Session): Session
            oauth_user_data (OAuthUserCreateSchema): The OAuth User data without username and with source and oa_id

        Returns:
            User: The created or updated user.

        Raises:
            DatabaseError: If there was an error while updating the user.
        """
        logger.debug("Creating or updating OAuth user")

        try:
            user = cls.get_user_by_username(db, oauth_user_data.username)

            if user is None:
                user_data = oauth_user_data.to_user_create_schema()
                user = cls._create(db, user_data, password_hasher=None)
                logger.info(f"OAuth user created: {oauth_user_data.username}")
            else:
                user._update_oauth_user(db, oauth_user_data)
                logger.info(f"OAuth user updated: {oauth_user_data.username}")

        except DatabaseError as e:
            logger.error(f"There was an error while creating/updating the user: {str(e)}")
            raise DatabaseError(f"There was an error while creating/updating the user: {str(e)}") from e
        return user


class OAuthAuthenticator:



    @staticmethod
    def authenticate(db: Session,
                     oauth_user_data: OAuthUserCreateSchema,
                     device_fingerprint: FingerPrintedData) -> AuthTokens:
        logger.info(f"Trying to create or update OAuth user with return auth data: {oauth_user_data.username}")
        user = OAuthUser.create_or_update_oauth_user(db, oauth_user_data)
        logger.debug(f"Authenticating OAuth user: {oauth_user_data.username}")

        authentication = user.authenticator().generate_auth_response_and_save_session(db, device_fingerprint)
        logger.info(f"Now user {oauth_user_data.username} in db and auth data returning")
        return authentication

