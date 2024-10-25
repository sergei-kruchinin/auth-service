# core > models > user.py

from sqlalchemy import Column, Integer, String, Boolean, DateTime, func
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import relationship, Session
from typing import Dict, List, Optional
import logging

from .base import Base
from core.schemas import *
from core.exceptions import AuthenticationError, UserAlreadyExistsError, DatabaseError
from core.token_service import TokenService, TokenType
from core.password_hash import PasswordHash
from core.models.user_session import UserSession

logger = logging.getLogger(__name__)


class User(Base):
    """
    Represents a user in the application.

    Attributes:
        id (int): The unique identifier for the user.
        username (str): The username name of the user.
        first_name (str): The first name of the user (optional).
        last_name (str): The last name of the user (optional).
        secret (str): The password hash or secret for the user (optional).
        is_admin (bool): Flag indicating whether the user has admin privileges.
        source (str): The source from which the user was created (e.g., 'manual', 'oauth') (optional).
        oa_id (str): The OAuth ID for the user (optional).
        created_at (datetime): The timestamp when the user was created.
        updated_at (datetime): The timestamp when the user was last updated.
    """

    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(128), unique=True, nullable=False)
    first_name = Column(String(128), nullable=True)
    last_name = Column(String(128), nullable=True)
    secret = Column(String(256), nullable=True)
    is_admin = Column(Boolean, nullable=False)
    source = Column(String(50), nullable=True)
    oa_id = Column(String(256), nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )
    updated_at = Column(
        DateTime(timezone=True),
        onupdate=func.now()
    )

    sessions = relationship("UserSession", back_populates="user")

    def __init__(self, user_data: UserCreateSchema):
        self.username = user_data.username
        self.first_name = user_data.first_name
        self.last_name = user_data.last_name
        self.secret = PasswordHash.generate_or_none(user_data.password)
        self.is_admin = bool(user_data.is_admin)
        self.source = user_data.source
        self.oa_id = user_data.oa_id

    # ### 2. User Management Methods ###

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
            users = db.query(cls).all()
            return {'users': [UserResponseSchema.from_orm(user).dict() for user in users]}
        except SQLAlchemyError as e:
            logger.error(f"There was an error while retrieving users: {str(e)}")
            raise DatabaseError(f"There was an error while retrieving users{str(e)}") from e

    # ### 3. User Creation Methods ###

    def set_oa_id_if_user_is_manual(self, db: Session) -> None:
        """
        Set the `oa_id` for a manually created user.

        This code cannot be moved to Schemas because `id` in Schemas is not present and so cannot be filled.

        Args:
            db (Session): The SQLAlchemy session to use for the database query.
        """
        try:
            if self.source == 'manual' and self.oa_id is None:
                self.oa_id = str(self.id)
                db.commit()
        except SQLAlchemyError as e:
            db.rollback()
            logger.error(f"There was an error while creating a user: {str(e)}")
            raise DatabaseError(f"There was an error while creating a user: {str(e)}") from e

    @classmethod
    def __create(cls, db: Session, user_data: UserCreateSchema) -> 'User':
        """
        Create a new user without checking if the user already exists.
        If user exists, raises a DatabaseError indicating user already exists.

        Args:
            db (Session): Session
            user_data (UserCreateSchema): The data to create a new user.

        Returns:
            Users: The newly created user.

        Raises:
            DatabaseError: If there was an error while creating a user.
            UserAlreadyExistsError: If user with the username already exists.
          """
        logger.debug("Creating new user")
        try:

            new_user = cls(user_data)
            db.add(new_user)
            db.commit()
            new_user.set_oa_id_if_user_is_manual(db)
            logger.info(f"User created successfully: {new_user.username}")
            return new_user
        except DatabaseError:
            raise
        except SQLAlchemyError as e:
            db.rollback()
            logger.error(f"There was an error while creating a user: {str(e)}")
            raise DatabaseError(f"There was an error while creating a user: {str(e)}") from e

    @classmethod
    def __get_user_by_username(cls, db: Session, username: str) -> Optional['User']:
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
            return db.query(cls).filter_by(username=username).first()
        except SQLAlchemyError as e:
            logger.error(f"There was an error while fetching the user: {str(e)}")
            raise DatabaseError(f"There was an error while fetching the user: {str(e)}") from e

    @classmethod
    def create_with_check(cls, db: Session, user_data: ManualUserCreateSchema) -> 'User':
        """
        Create a new user after checking if the user already exists.
        If user exists, raises a UserAlreadyExistsError indicating user already exists.

        Args:
            db (Session): Session
            user_data (dict): The data to create a new user.

        Returns:
            Users: The newly created user.

        Raises:
            UserAlreadyExistsError: If user with the username already exists.
        """

        logger.debug("Creating new user with check")

        if cls.__get_user_by_username(db, user_data.username) is not None:
            logger.warning(f"User with username {user_data.username} already exists")
            raise UserAlreadyExistsError(f"User with username {user_data.username} already exists")

        try:
            user_data = user_data.to_user_create_schema()
            user = cls.__create(db, user_data)
            return user
        except DatabaseError as e:
            logger.error(f"Database error occurred: {str(e)}")
            raise
        except SQLAlchemyError as e:
            logger.error(f"There was an error while creating user: {str(e)}")
            raise DatabaseError(f"There was an error while creating user {str(e)}") from e

    def __update_oauth_user(self, db: Session, oauth_user_data: OAuthUserCreateSchema) -> None:
        """
        Update an existing OAuth user with new data.

        Args:
            db (Session): Session
            oauth_user_data (OAuthUserCreateSchema): New data for updating the user
        """
        self.first_name = oauth_user_data.first_name
        self.last_name = oauth_user_data.last_name
        self.is_admin = oauth_user_data.is_admin

        try:
            db.commit()
        except SQLAlchemyError as e:
            logger.error(f"There was an error while updating the user: {str(e)}")
            db.rollback()
            raise DatabaseError(str(e)) from e

    @classmethod
    def create_or_update_oauth_user(cls, db: Session, oauth_user_data: OAuthUserCreateSchema) -> 'User':
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
            user = cls.__get_user_by_username(db, oauth_user_data.username)

            if user is None:
                user_data = oauth_user_data.to_user_create_schema()
                user = cls.__create(db, user_data)
                logger.info(f"OAuth user created: {user.username}")
            else:
                user.__update_oauth_user(db, oauth_user_data)
                logger.info(f"OAuth user updated: {user.username}")

        except DatabaseError as e:
            logger.error(f"There was an error while creating/updating the user: {str(e)}")
            raise DatabaseError(f"There was an error while creating/updating the user: {str(e)}") from e
        return user

    # ### 4. Authentication Methods ###

    def __generate_auth_response_and_save_session(self,
                                                  db: Session,
                                                  device_fingerprint: FingerPrintedData) -> AuthTokens:
        """
        Generate authentication response including JWT token and its expiration time.

        Returns:
            Dict: The generated token and expiration time.
        """
        payload = TokenPayload(
            id=self.id,
            username=self.username,
            first_name=self.first_name,
            last_name=self.last_name,
            is_admin=self.is_admin,
            device_fingerprint=device_fingerprint.device_fingerprint
        )
        logger.info("Generating access and refresh token")
        tokens = {}

        for token_type in TokenType:
            logger.info(f"Generating {token_type} token")
            token_response = TokenService.generate_token(payload, token_type)
            logger.info(f"Token")
            tokens[token_type.value] = TokenData(value=token_response.value,
                                                 expires_in=token_response.expires_in)
        logger.info("Access and refresh token generates")

        session_data = UserSessionData(
            user_id=self.id,
            ip_address=device_fingerprint.ip,
            user_agent=device_fingerprint.user_agent,
            accept_language=device_fingerprint.accept_language,
            refresh_token=tokens[TokenType.REFRESH.value].value,
            expires_in=tokens[TokenType.REFRESH.value].expires_in)
        print('SESSION:', session_data)
        UserSession.create_session(db, session_data)

        return AuthTokens(tokens=tokens, user_id=self.id)

    @classmethod
    def authenticate(cls, db: Session, auth_request: AuthRequestFingerPrinted) -> AuthTokens:
        """
        Authenticate user with username and password.

        Args:
            auth_request (AuthRequestFingerPrinted): The username and plaintext password of the user.
            db (Session): Session
        Returns:
            AuthTokens: The generated access and refresh tokens and their expiration times.
        Raises:
            AuthenticationError: If username or password is invalid.
        """
        logger.debug(f"Authenticating user: {auth_request.username}")
        try:
            user = db.query(cls).filter_by(username=auth_request.username).first()

            if user is None or not PasswordHash.check(str(user.secret), auth_request.password):
                logger.warning(f"Authentication failed for user: {auth_request.username}")
                raise AuthenticationError('Invalid username or invalid password')
            logger.info(f"User authenticated successfully: {user.username}")
            #     user.id,
            return user.__generate_auth_response_and_save_session(db, auth_request)

        except SQLAlchemyError as e:
            logger.error(f"There was an error accessing the database: {str(e)}")
            raise DatabaseError(f"There was an error accessing the database: {str(e)}") from e

    def authenticate_oauth(self, db: Session, device_fingerprint: FingerPrintedData) -> AuthTokens:
        """
        Authenticate OAuth user

        Returns:
            Dict: The generated token and expiration time.

        """
        logger.debug(f"Authenticating OAuth user: {self.username}")
        return self.__generate_auth_response_and_save_session(db, device_fingerprint)

    # ### 5. Object Representation Methods ###

    def __repr__(self) -> str:
        """
        Represent user information for debugging/logging.

        Returns:
            str: Representation of the user's username.
        """

        return f'<User(username={self.username}, id={self.id}, is_admin={self.is_admin})>'
