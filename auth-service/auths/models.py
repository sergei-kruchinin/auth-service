from passlib.context import CryptContext
from sqlalchemy.sql import func
from . import db
from .schemas import AuthPayload, UserCreateSchema, OauthUserCreateSchema, UserResponseSchema
from .exceptions import *
from .token_service import TokenService
from typing import Dict, List


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

    # ### 1. Login and Password Handling Methods ###

    @classmethod
    def create_composite_login(cls, source: str, oa_id: str) -> str:
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
        except Exception as e:
            raise DatabaseError(f"There was an error while retrieving users{str(e)}") from e

    # ### 3. User Creation Methods ###

    @classmethod
    def create(cls, data: dict) -> 'Users':
        """
        Create a new user without checking if the user already exists.
        If user exists, raises a DatabaseError indicating user already exists.

        Args:
            data (dict): The data to create a new user.

        Returns:
            Users: The newly created user.

        Raises:
            DatabaseError: If there was an error while creating a user.
            UserAlreadyExistsError: If user with the login already exists.
          """
        validated_data = UserCreateSchema(**data)

        hashed_password = cls.generate_password_hash_or_none(validated_data.password)
        is_admin = bool(validated_data.is_admin)
        try:
            new_user = cls(
                login=validated_data.login,
                first_name=validated_data.first_name,
                last_name=validated_data.last_name,
                secret=hashed_password,
                is_admin=is_admin,
                source=validated_data.source,
                oa_id=validated_data.oa_id
            )
            db.session.add(new_user)
            db.session.commit()

            if new_user.source == 'manual' and new_user.oa_id is None:
                new_user.oa_id = str(new_user.id)
                db.session.commit()

            return new_user
        except Exception as e:
            db.session.rollback()
            raise DatabaseError(f"There was an error while creating a user: {str(e)}") from e

    @classmethod
    def create_with_check(cls, data: dict) -> 'Users':
        """
        Create a new user after checking if the user already exists.
        If user exists, raises a UserAlreadyExistsError indicating user already exists.

        Args:
            data (dict): The data to create a new user.

        Returns:
            Users: The newly created user.

        Raises:
            UserAlreadyExistsError: If user with the login already exists.
        """
        validated_data = UserCreateSchema(**data)

        if cls.query.filter_by(login=validated_data.login).first():
            raise UserAlreadyExistsError(f"User with login {validated_data.login} already exists")
        user = cls.create(validated_data.dict())
        return user

    @classmethod
    def create_or_update_oauth_user(
            cls,
            first_name: str,
            last_name: str,
            is_admin: bool,
            source: str,
            oa_id: str
        ) -> 'Users':
        """
        Create or update a user for OAuth 2.0 authorization.
        It always updates user data from OAuth Provider,
        if it is the first authorization -- create user data in the database.

        Args:
            first_name (str): The first name of the user.
            last_name (str): The last name of the user.
            is_admin (bool): Boolean indicating if the user is an admin.
            source (str): The source of the user.
            oa_id (str): The OAuth ID.

        Returns:
            Users: The created or updated user.

        Raises:
            DatabaseError: If there was an error while updating the user.
        """
        login = cls.create_composite_login(source, oa_id)
        is_admin = bool(is_admin)

        # is user already in database?
        user = cls.query.filter_by(login=login).first()

        try:
            if user is None:
                # User doesn't exist, so create a new one
                # print(login, first_name, last_name, is_admin, source, oa_id)

                user_data = OauthUserCreateSchema(
                    login=login,
                    first_name=first_name,
                    last_name=last_name,
                    password=None,  # There is no password for OAuth
                    is_admin=is_admin,
                    source=source,
                    oa_id=oa_id
                )
                user = cls.create(user_data.dict())
                return user
            else:
                # User exists, update the existing user information with the new details
                user.first_name = first_name
                user.last_name = last_name
                user.is_admin = is_admin

                db.session.commit()
                return user
        except Exception as e:
            db.session.rollback()
            raise DatabaseError(f"There was an error while updating the user: {str(e)}") from e

    # ### 4. Authentication Methods ###

    @classmethod
    def authenticate(cls, login: str, password: str) -> str:
        """
        Authenticate user with login and password.

        Args:
            login (str): The login of the user.
            password (str): The plaintext password of the user.

        Returns:
            str: A generated token for the authenticated user.

        Raises:
            AuthenticationError: If login or password is invalid.
        """
        if not password:
            raise AuthenticationError('Password not specified')

        user = cls.query.filter(cls.login == login).first()

        if user is None or not cls.check_password_hash(user.secret, password):
            raise AuthenticationError('Invalid login or invalid password')

        payload = AuthPayload(id=user.id, login=user.login, first_name=user.first_name, last_name=user.last_name,
                              is_admin=user.is_admin)
        return TokenService.generate_token(payload)

    @classmethod
    def authenticate_oauth(cls, login: str) -> str:
        """
        Authenticate OAuth user with login <source:oa_id>.

        Args:
            login (str): The login <source:oa_id> of the OAuth user.

        Returns:
            str: A generated token for the authenticated user.

        Raises:
            DatabaseError: If there is an error while syncing from social service.
        """
        user = cls.query.filter_by(login=login).first()

        if user is None:
            raise DatabaseError('Error occurred while syncing from social service')

        payload = AuthPayload(id=user.id, login=user.login, first_name=user.first_name, last_name=user.last_name,
                              is_admin=user.is_admin)
        return TokenService.generate_token(payload)

    # ### 5. Object Representation Methods ###

    def __repr__(self) -> str:
        """
        Represent user information for debugging/logging.

        Returns:
            str: Representation of the user's login.
        """

        return f'User {self.login}'
