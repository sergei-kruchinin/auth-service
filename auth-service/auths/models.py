import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import jwt
from passlib.context import CryptContext
from sqlalchemy.sql import func

from . import db

AUTH_SECRET = os.getenv('AUTH_SECRET')
EXPIRES_SECONDS = int(os.getenv('EXPIRES_SECONDS'))


class AuthenticationError(Exception):
    pass


class TokenError(AuthenticationError):  # now a subclass of AuthenticationError
    pass


class TokenBlacklisted(TokenError):
    pass


class TokenExpired(TokenError):
    pass


class TokenInvalid(TokenError):
    pass


class DatabaseError(Exception):
    pass


@dataclass
class AuthPayload:
    id: int
    login: str
    first_name: str
    last_name: str
    is_admin: bool
    exp: datetime

    def __init__(self, id, login, first_name, last_name, is_admin):
        self.id = id
        self.login = login
        self.first_name = first_name
        self.last_name = last_name
        self.is_admin = is_admin
        self.exp = datetime.now(timezone.utc) + timedelta(seconds=EXPIRES_SECONDS)


@dataclass
class AuthResponse:
    token: str
    expires_in: int


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
        except AttributeError:
            raise TypeError("Password should be a string")

    @classmethod
    def list(cls):
        users = cls.query.all()

        user_data = [
            {
                "id": user.id,
                'login': user.login,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "is_admin": user.is_admin,
                'source': user.source,
                'oa_id': user.oa_id
            } for user in users
        ]

        return json.dumps(user_data, ensure_ascii=False) if user_data else {'success': False}  # For debug
        # return json.dumps(user_data) if user_data else {'success': False}  # For production

    @classmethod
    def create(cls, login, first_name, last_name, password, is_admin, source='manual', oa_id=None):

        hashed_password = cls.generate_password_hash_or_none(password)

        is_admin = bool(is_admin)
        try:

            new_user = cls(login=login, first_name=first_name, last_name=last_name, secret=hashed_password,
                           is_admin=is_admin, source=source, oa_id=oa_id)
            db.session.add(new_user)
            db.session.commit()
            return True
        except Exception:
            db.session.rollback()
            return False

    # Method for using by OAuth 2.0 authorization
    # May be to do: source and oa_id params.
    @classmethod
    def create_or_update(cls, login, first_name, last_name, password, is_admin, source, oa_id):

        hashed_password = cls.generate_password_hash_or_none(password)

        is_admin = bool(is_admin)
        user = cls.query.filter_by(login=login).first()

        if user is None:
            # User doesn't exist, so create a new one
            user = cls.create(login, first_name, last_name, hashed_password, is_admin, source, oa_id)
        else:
            # User exists, update the existing user information
            user.first_name = first_name
            user.last_name = last_name
            user.secret = hashed_password
            user.is_admin = is_admin
            # user.source = source  #  Not changeable information
            # user.oa_id = oa_id    #  Not changeable information
            db.session.commit()

        return user

    @classmethod
    def authenticate(cls, login, password):
        if not password:
            raise AuthenticationError('Invalid login or password')

        user = cls.query.filter(cls.login == login).first()

        if user is None or not cls.check_password_hash(user.secret, password):
            raise AuthenticationError('Invalid login or password')

        payload = AuthPayload(user.id, user.login, user.first_name, user.last_name, user.is_admin)
        encoded_jwt = jwt.encode(payload.__dict__, AUTH_SECRET, algorithm='HS256')
        response = AuthResponse(encoded_jwt, EXPIRES_SECONDS)

        return response.__dict__


    @classmethod
    def authenticate_oauth(cls, login):
        user = cls.query.filter_by(login=login).first()

        if user is None:
            raise DatabaseError('Error while syncking from social service has occured')

        payload = AuthPayload(user.id, user.login, user.first_name, user.last_name, user.is_admin)
        encoded_jwt = jwt.encode(payload.__dict__, AUTH_SECRET, algorithm='HS256')
        response = AuthResponse(encoded_jwt, EXPIRES_SECONDS)
        return response.__dict__

    @staticmethod
    def auth_verify(token):
        if Blacklist.is_blacklisted(token):
            raise TokenBlacklisted("Token invalidated. Get new one")
        else:
            try:
                decoded = jwt.decode(token, AUTH_SECRET, algorithms=['HS256'])
                return decoded
            except jwt.ExpiredSignatureError:
                raise TokenExpired("Token expired. Get new one")
            except jwt.InvalidTokenError:
                raise TokenInvalid("Invalid token")


    def __repr__(self):
        return f'User {self.login}'


class Blacklist(db.Model):
    token = db.Column(db.String(256), primary_key=True, nullable=False)

    @classmethod
    def add_token(cls, black_token):
        black_token_record = cls(token=black_token)
        db.session.add(black_token_record)
        db.session.commit()

    @classmethod
    def is_blacklisted(cls, token):
        if cls.query.get(token):
            return True
        else:
            return False

    def __repr__(self):
        return f'In blacklist: {self.token}'
