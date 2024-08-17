from . import db
from sqlalchemy.sql import func
from flask import jsonify
import os
import jwt
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass

AUTH_SECRET = os.getenv('AUTH_SECRET')
EXPIRES_SECONDS = int(os.getenv('EXPIRES_SECONDS'))


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
    @classmethod
    def list(cls):
        users = cls.query.all()
        if users:
            user_data = [{
                "id": user.id,
                'login': user.login,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "is_admin": user.is_admin
            }
                for user in users
            ]
            return jsonify(user_data)
        else:
            return {'success': False}

    @classmethod
    def create(cls, login, first_name, last_name, secret, is_admin):
        try:
            print(f'login={login}, first_name={first_name}, last_name={last_name}, secret={secret}, is_admin={is_admin}')
            new_user = cls(login=login, first_name=first_name, last_name=last_name, secret=secret, is_admin=is_admin)
            db.session.add(new_user)
            db.session.commit()
            return True
        except Exception:
            db.session.rollback()
            return False

    @classmethod
    def authenticate(cls, login, secret):
        if secret == '' or secret is None:
            return False

        user = cls.query.filter(cls.login == login,
                                cls.secret == secret).first()
        if user is not None:
            payload = AuthPayload(user.id, user.login, user.first_name, user.last_name, user.is_admin)
            encoded_jwt = jwt.encode(payload.__dict__, AUTH_SECRET, algorithm='HS256')
            response = AuthResponse(encoded_jwt, EXPIRES_SECONDS)
            return response.__dict__
        else:
            return False

    @staticmethod
    def auth_verify(token):
        if Blacklist.is_blacklisted(token):
            return {"success": False, "message": "Token invalidated. Get new one"}
        else:
            try:
                decoded = jwt.decode(token, AUTH_SECRET, algorithms=['HS256'])
                return decoded
            except jwt.ExpiredSignatureError:
                return {"success": False, "message": "Token expired. Get new one"}
            except jwt.InvalidTokenError:
                return {"success": False, "message": "Invalid Token"}

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
