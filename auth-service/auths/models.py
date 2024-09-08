# models.py
from passlib.context import CryptContext
# from sqlalchemy import Column, Integer, String, Boolean, DateTime
from sqlalchemy.sql import func
from . import db
from .schemas import (AuthRequest, AuthPayload,
                      OAuthUserCreateSchema,
                      UserCreateInputSchema, UserResponseSchema)
from .exceptions import *
from .token_service import TokenService
from typing import Dict, List
from sqlalchemy.exc import SQLAlchemyError
# from .database import Base


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(128), unique=True, nullable=False)
    first_name = db.Column(db.String(128), nullable=True)
    last_name = db.Column(db.String(128), nullable=True)
    secret = db.Column(db.String(256), nullable=True)
    is_admin = db.Column(db.Boolean, nullable=False)
    source = db.Column(db.String(50), nullable=True)
    oa_id = db.Column(db.String(256), nullable=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        server_default=func.now()
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        onupdate=func.now()
    )
    pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

    # ### 1. Password Handling Methods ###

    @staticmethod
    def create_composite_login(source: str, oa_id: str) -> str:
        """
        Generate a composite login from the source and oa_id.

        Args:
            source (str): The source of the user.
            oa_id (str): The OAuth ID.

        Returns:
            str: The composite login string.
        """
        return f"{source}:{oa_id}"

    @classmethod
    def generate_password_hash(cls, password: str) -> str:
        """
        Generate a salted hash from plaintext password.

        Args:
            password (str): The plaintext password.

        Returns:
            str: The hashed password.
        """
        return cls.pwd_context.hash(password)

    @classmethod
    def check_password_hash(cls, hashed_password: str, plain_password: str) -> bool:
        """
        Verify if the provided plaintext password matches the hashed password.

        Args:
            hashed_password (str): The hashed password stored in the database.
            plain_password (str): The plaintext password provided by the user.

        Returns:
            bool: True if the passwords match, False otherwise.
        """
        return cls.pwd_context.verify(plain_password, hashed_password)

    @classmethod
    def generate_password_hash_or_none(cls, password: str | None) -> str | None:
        """
        Generate a password hash or return None if the password is None.

        Args:
            password (str or None): The plaintext password or None.

        Returns:
            str or None: The hashed password or None.
        """
        if password is None:
            return None
        try:
            return cls.generate_password_hash(password)
        except AttributeError as e:
            raise TypeError("Password should be a string") from e

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
            users = cls.query.all()
            return {'users': [UserResponseSchema.from_orm(user).dict() for user in users]}
        except SQLAlchemyError as e:
            raise DatabaseError(f"There was an error while retrieving users{str(e)}") from e

    # ### 3. User Creation Methods ###

    @classmethod
    def __create(cls, user_data: OAuthUserCreateSchema | UserCreateInputSchema) -> 'Users':
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

        hashed_password = cls.generate_password_hash_or_none(user_data.password)
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
            db.session.add(new_user)
            db.session.commit()

            if new_user.source == 'manual' and new_user.oa_id is None:
                new_user.oa_id = str(new_user.id)
                db.session.commit()

            return new_user
        except SQLAlchemyError as e:
            db.session.rollback()
            raise DatabaseError(f"There was an error while creating a user: {str(e)}") from e

    @classmethod
    def create_with_check(cls, user_data: UserCreateInputSchema) -> 'Users':
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

        try:
            if cls.query.filter_by(login=user_data.login).first():
                raise UserAlreadyExistsError(f"User with login {user_data.login} already exists")

            user = cls.__create(user_data)
            return user

        except SQLAlchemyError as e:
            raise DatabaseError(f"There was an error while creating user {str(e)}") from e

    @classmethod
    def create_or_update_oauth_user(cls, oauth_user_data: OAuthUserCreateSchema) -> 'Users':
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

        # oauth_user_data.login = cls.create_composite_login(oauth_user_data.source, oauth_user_data.oa_id)
        try:
            # is user already in database?
            user = cls.query.filter_by(login=oauth_user_data.login).first()

            if user is None:
                # User doesn't exist, so create a new one
                # print(login, first_name, last_name, is_admin, source, oa_id)

                user = cls.__create(oauth_user_data)
                return user
            else:
                # User exists, update the existing user information with the new details
                user.first_name = oauth_user_data.first_name
                user.last_name = oauth_user_data.last_name
                user.is_admin = oauth_user_data.is_admin

                db.session.commit()
                return user
        except SQLAlchemyError as e:
            db.session.rollback()
            raise DatabaseError(f"There was an error while updating the user: {str(e)}") from e

    # ### 4. Authentication Methods ###

    def __generate_auth_response(self) -> Dict:
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
        auth_response = TokenService.generate_token(payload)
        # TODO not dict, but auth_response (?)
        return auth_response.dict()

    @classmethod
    def authenticate(cls, auth_request: AuthRequest) -> Dict:
        """
        Authenticate user with login and password.

        Args:
            auth_request (AuthRequest): The login and plaintest password of the user.
        Returns:
            Dict: The generated token and expiration time.
        Raises:
            AuthenticationError: If login or password is invalid.
        """
        try:
            user = cls.query.filter(cls.login == auth_request.login).first()

            if user is None or not cls.check_password_hash(user.secret, auth_request.password):
                raise AuthenticationError('Invalid login or invalid password')

            return user.__generate_auth_response()

        except SQLAlchemyError as e:
            raise DatabaseError(f"There was an error accessing the database: {str(e)}") from e

    def authenticate_oauth(self) -> Dict:
        """
        Authenticate OAuth user

        Returns:
            Dict: The generated token and expiration time.

        """

        return self.__generate_auth_response()

    # ### 5. Object Representation Methods ###

    def __repr__(self) -> str:
        """
        Represent user information for debugging/logging.

        Returns:
            str: Representation of the user's login.
        """

        return f'User {self.login}'
