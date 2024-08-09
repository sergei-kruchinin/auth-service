from . import db
from sqlalchemy.sql import func
from flask import jsonify
import os
import jwt
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass

# TODO: move AUTH_SECRECT and EXPIRES_SECONDS to file of ENV
AUTH_SECRET = 'secret'
EXPIRES_SECONDS = 600  # int(os.getenv('EXPIRES_SECONDS'))

@dataclass
class AuthPayload:
    id: int
    name: str
    is_admin: bool
    exp: datetime

    def __init__(self, user_id, user_name, is_admin):
        # TODO: move to global var, reading it from file or ENV
        expires_seconds = EXPIRES_SECONDS  # int(os.getenv('EXPIRES_SECONDS'))
        self.id = user_id
        self.name = user_name
        self.is_admin = is_admin
        self.exp = datetime.now(timezone.utc) + timedelta(seconds=expires_seconds)


@dataclass
class AuthResponse:
    token: str
    expires_in: int

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(128), unique=True, nullable=False)
    user_secret = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        server_default=func.now()
    )

    @classmethod
    def list(cls):
        users = cls.query.all()
        if users:
            user_data = [{
                "id": user.id,
                "name": user.user_name,
                "is_admin": user.is_admin
            }
                for user in users
            ]
            return jsonify(user_data)
        else:
            return {'success': False}

    @classmethod
    def create(cls, name, secret, flag_admin):

        try:
            new_user = cls(user_name=name, user_secret=secret, is_admin=flag_admin)
            db.session.add(new_user)
            db.session.commit()
            return True
        except Exception:
            db.session.rollback()
            return False

    @classmethod
    def authenticate(cls, user_name, user_proposes_secret):
        # TODO move to class users
        user = cls.query.filter(cls.user_name == user_name,
                                  cls.user_secret == user_proposes_secret).first()
        if user is not None:
            payload = AuthPayload(user.id, user.user_name, user.is_admin)
            encoded_jwt = jwt.encode(payload.__dict__, AUTH_SECRET, algorithm='HS256')
            response = AuthResponse(encoded_jwt, EXPIRES_SECONDS)
            return response.__dict__
        else:
            return False

    @staticmethod
    def auth_verify(token):
        # TODO move to class Users (?) or Blacklist (!)
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
    return f'User {self.user_name} secret {self.user_secret}'


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
