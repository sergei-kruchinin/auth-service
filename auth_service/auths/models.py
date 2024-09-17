# auths > models.py

from sqlalchemy import Column, Integer, String, Boolean, DateTime, func
from sqlalchemy.exc import SQLAlchemyError
from auth_service.auths import Base, db_session
from .schemas import (AuthRequest, AuthPayload, AuthResponse,
                      OAuthUserCreateSchema, TokenData,
                      UserCreateInputSchema, UserResponseSchema)
from .exceptions import AuthenticationError, UserAlreadyExistsError, DatabaseError
from .token_service import TokenService, TokenType
from .password_hash import PasswordHash
from typing import Dict, List
import logging
logger = logging.getLogger(__name__)


class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    login = Column(String(128), unique=True, nullable=False)
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

    # ### 2. User Management Methods ###

    @classmethod
    def list(cls) -> Dict[str, List[Dict]]:
        """
        Retrieve the list of all users.

        Returns:
            dict: A dictionary with a list of all users.

        Raises:
            DatabaseError: If there was an error while retrieving users.
        """
        try:
            users = db_session.query(cls).all()
            return {'users': [UserResponseSchema.from_orm(user).dict() for user in users]}
        except SQLAlchemyError as e:
            logger.error(f"There was an error while retrieving users: {str(e)}")
            raise DatabaseError(f"There was an error while retrieving users{str(e)}") from e

    # ### 3. User Creation Methods ###

    @classmethod
    def __create(cls, user_data: OAuthUserCreateSchema | UserCreateInputSchema) -> 'User':
        """
        Create a new user without checking if the user already exists.
        If user exists, raises a DatabaseError indicating user already exists.

        Args:
            user_data (OAuthUserCreateSchema | UserCreateInputSchema): The data to create a new user.

        Returns:
            Users: The newly created user.

        Raises:
            DatabaseError: If there was an error while creating a user.
            UserAlreadyExistsError: If user with the login already exists.
          """
        logger.debug("Creating new user")
        hashed_password = PasswordHash.generate_or_none(user_data.password)
        is_admin = bool(user_data.is_admin)
        try:
            new_user = cls(
                login=user_data.login,
                first_name=user_data.first_name,
                last_name=user_data.last_name,
                secret=hashed_password,
                is_admin=is_admin,
                source=user_data.source,
                oa_id=user_data.oa_id
            )
            db_session.add(new_user)
            db_session.commit()

            if new_user.source == 'manual' and new_user.oa_id is None:
                new_user.oa_id = str(new_user.id)
                db_session.commit()
            logger.info(f"User created successfully: {new_user.login}")
            return new_user
        except SQLAlchemyError as e:
            db_session.rollback()
            logger.error(f"There was an error while creating a user: {str(e)}")
            raise DatabaseError(f"There was an error while creating a user: {str(e)}") from e

    @classmethod
    def create_with_check(cls, user_data: UserCreateInputSchema) -> 'User':
        """
        Create a new user after checking if the user already exists.
        If user exists, raises a UserAlreadyExistsError indicating user already exists.

        Args:
            user_data (dict): The data to create a new user.

        Returns:
            Users: The newly created user.

        Raises:
            UserAlreadyExistsError: If user with the login already exists.
        """
        # TODO further: class constructor instead of method (?)
        logger.debug("Creating new user with check")
        try:
            if db_session.query(cls).filter_by(login=user_data.login).first():
                logger.warning(f"User with login {user_data.login} already exists")
                raise UserAlreadyExistsError(f"User with login {user_data.login} already exists")

            user = cls.__create(user_data)
            return user

        except SQLAlchemyError as e:
            logger.error(f"There was an error while creating user: {str(e)}")
            raise DatabaseError(f"There was an error while creating user {str(e)}") from e

    @classmethod
    def create_or_update_oauth_user(cls, oauth_user_data: OAuthUserCreateSchema) -> 'User':
        """
        Create or update a user for OAuth 2.0 authorization.
        It always updates user data from OAuth Provider,
        if it is the first authorization -- create user data in the database.

        Args:
            oauth_user_data (OAuthUserCreateSchema): The OAuth User data without login and with source and oa_id

        Returns:
            Users: The created or updated user.

        Raises:
            DatabaseError: If there was an error while updating the user.
        """

        # TODO Further : Single Table Inheritance (STI) class OAuthUser
        # and it's constructor (?)

        logger.debug("Creating or updating OAuth user")
        try:
            # is user already in database?
            user = db_session.query(cls).filter_by(login=oauth_user_data.login).first()

            if user is None:
                # User doesn't exist, so create a new one
                user = cls.__create(oauth_user_data)
                logger.info(f"OAuth user created: {user.login}")
                return user
            else:
                # User exists, update the existing user information with the new details
                user.first_name = oauth_user_data.first_name
                user.last_name = oauth_user_data.last_name
                user.is_admin = oauth_user_data.is_admin

                db_session.commit()
                logger.info(f"OAuth user updated: {user.login}")
                return user
        except SQLAlchemyError as e:
            db_session.rollback()
            logger.error(f"There was an error while updating the user: {str(e)}")
            raise DatabaseError(f"There was an error while updating the user: {str(e)}") from e

    # ### 4. Authentication Methods ###

    def __generate_auth_response(self) -> AuthResponse:
        """
        Generate authentication response including JWT token and its expiration time.

        Returns:
            Dict: The generated token and expiration time.
        """
        payload = AuthPayload(
            id=self.id,
            login=self.login,
            first_name=self.first_name,
            last_name=self.last_name,
            is_admin=self.is_admin
        )
        logger.info("Generating access and refresh token")
        tokens = {}

        for token_type in TokenType:
            logger.info(f"Generating {token_type} token")
            token_response = TokenService.generate_token(payload, token_type)
            logger.info(f"Token")
            tokens[token_type.value] = TokenData(value=token_response.value, expires_in=token_response.expires_in)
        logger.info("Access and refresh token generates")

        return AuthResponse(tokens=tokens)


    @classmethod
    def authenticate(cls, auth_request: AuthRequest) -> AuthResponse:
        """
        Authenticate user with login and password.

        Args:
            auth_request (AuthRequest): The login and plaintext password of the user.
        Returns:
            AuthResponse: The generated access and refresh tokens and their expiration times.
        Raises:
            AuthenticationError: If login or password is invalid.
        """
        logger.debug(f"Authenticating user: {auth_request.login}")
        try:
            user = db_session.query(cls).filter_by(login=auth_request.login).first()

            if user is None or not PasswordHash.check(user.secret, auth_request.password):
                logger.warning(f"Authentication failed for user: {auth_request.login}")
                raise AuthenticationError('Invalid login or invalid password')
            logger.info(f"User authenticated successfully: {user.login}")
            return user.__generate_auth_response()

        except SQLAlchemyError as e:
            logger.error(f"There was an error accessing the database: {str(e)}")
            raise DatabaseError(f"There was an error accessing the database: {str(e)}") from e

    def authenticate_oauth(self) -> AuthResponse:
        """
        Authenticate OAuth user

        Returns:
            Dict: The generated token and expiration time.

        """
        logger.debug(f"Authenticating OAuth user: {self.login}")
        return self.__generate_auth_response()

    # ### 5. Object Representation Methods ###

    def __repr__(self) -> str:
        """
        Represent user information for debugging/logging.

        Returns:
            str: Representation of the user's login.
        """

        return f'User {self.login}'
