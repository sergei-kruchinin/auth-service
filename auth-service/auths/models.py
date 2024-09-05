import os
import jwt
from passlib.context import CryptContext
from sqlalchemy.sql import func
from . import db
from .schemas import AuthPayload, AuthResponse, UserResponseSchema
from .exceptions import *

AUTH_SECRET = os.getenv('AUTH_SECRET')
EXPIRES_SECONDS = int(os.getenv('EXPIRES_SECONDS'))


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

    @classmethod
    def create_composite_login(cls, source, oa_id):
        return f"{source}:{oa_id}"

    # Generate salted hash from password
    @classmethod
    def generate_password_hash(cls, password):
        return cls.pwd_context.hash(password)

    # Check equals of hashed password and presented password
    @classmethod
    def check_password_hash(cls, hashed_password, plain_password):
        return cls.pwd_context.verify(plain_password, hashed_password)

    @classmethod
    def generate_password_hash_or_none(cls, password):
        if password is None:
            return None
        try:
            return cls.generate_password_hash(password)
        except AttributeError as e:
            raise TypeError("Password should be a string") from e

    @classmethod
    def list(cls):
        try:
            users = cls.query.all()
            return {'users': [UserResponseSchema.from_orm(user).dict() for user in users]}
        except Exception as e:
            raise DatabaseError(f"There was an error while retrieving users{str(e)}") from e

    @classmethod
    def create(cls, login, first_name, last_name, password, is_admin, source, oa_id):
        """
          Check if user exists before creating a new user.

          If user exists, raises a UserAlreadyExistsError.

          Creates a new system user (not oauth)
          """
        if cls.query.filter_by(login=login).first():
            raise UserAlreadyExistsError(f"User with login {login} already exists")

        hashed_password = cls.generate_password_hash_or_none(password)
        is_admin = bool(is_admin)
        try:
            new_user = cls(login=login, first_name=first_name, last_name=last_name, secret=hashed_password,
                           is_admin=is_admin, source=source, oa_id=oa_id)

            db.session.add(new_user)
            db.session.commit()

            if new_user.source == 'manual' and new_user.oa_id is None:
                new_user.oa_id = str(new_user.id)
                db.session.commit()

            return new_user
        except Exception as e:
            db.session.rollback()
            raise DatabaseError(str(e)) from e

    # Method for using by OAuth 2.0 authorization
    # It's always updates user data from OAuth Provider,
    # if the first authorization -- create user data at database
    @classmethod
    def create_or_update_oauth_user(cls, first_name, last_name, is_admin, source='manual', oa_id=None):

        login = cls.create_composite_login(source, oa_id)
        #  hashed_password = cls.generate_password_hash_or_none(password)

        is_admin = bool(is_admin)
        user = cls.query.filter_by(login=login).first()

        try:
            if user is None:
                # User doesn't exist, so create a new one
                user = cls.create(login, first_name, last_name, None, is_admin, source, oa_id)
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
            raise DatabaseError("There was an error while updating the user") from e

    @staticmethod
    def _generate_token(user):
        payload = AuthPayload(id=user.id, login=user.login, first_name=user.first_name, last_name=user.last_name,
                              is_admin=user.is_admin)
        encoded_jwt = jwt.encode(payload.dict(), AUTH_SECRET, algorithm='HS256')
        response = AuthResponse(token=encoded_jwt, expires_in=EXPIRES_SECONDS)
        return response.dict()

    @classmethod
    def authenticate(cls, login, password):
        if not password:
            raise AuthenticationError('Password not specified')

        user = cls.query.filter(cls.login == login).first()

        if user is None or not cls.check_password_hash(user.secret, password):
            raise AuthenticationError('Invalid login or invalid password')
        return cls._generate_token(user)

    @classmethod
    def authenticate_oauth(cls, login):
        user = cls.query.filter_by(login=login).first()

        if user is None:
            raise DatabaseError('Error occurred while syncing from social service')

        return cls._generate_token(user)

    @staticmethod
    def auth_verify(token):
        try:
            if Blacklist.is_blacklisted(token):
                raise TokenBlacklisted("Token invalidated.")
        except DatabaseError as e:
            raise DatabaseError('Error checking if token is blacklisted') from e

        try:
            decoded = jwt.decode(token, AUTH_SECRET, algorithms=['HS256'])
            return decoded
        except jwt.ExpiredSignatureError as e:
            raise TokenExpired("Token expired.") from e
        except jwt.InvalidTokenError as e:
            raise TokenInvalid("Invalid token") from e

    def __repr__(self):
        return f'User {self.login}'


class Blacklist(db.Model):
    token = db.Column(db.String(256), primary_key=True, nullable=False)

    @classmethod
    def add_token(cls, black_token):
        try:
            black_token_record = cls(token=black_token)
            db.session.add(black_token_record)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            raise DatabaseError(f"Error adding token to blacklist: {str(e)}") from e

    @classmethod
    def is_blacklisted(cls, token):
        try:
            return bool(cls.query.get(token))
        except Exception as e:
            raise DatabaseError(f"Error checking if token is blacklisted: {str(e)}") from e

    def __repr__(self):
        return f'In blacklist: {self.token}'
