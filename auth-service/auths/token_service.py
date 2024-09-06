import jwt
import os
from datetime import datetime, timezone, timedelta
from typing import Dict
from .schemas import AuthPayload, AuthResponse
from . import db
from .exceptions import TokenBlacklisted, TokenExpired, TokenInvalid, DatabaseError

AUTH_SECRET = os.getenv('AUTH_SECRET')
EXPIRES_SECONDS = int(os.getenv('EXPIRES_SECONDS'))


class TokenService:
    @staticmethod
    def generate_token(payload: AuthPayload) -> Dict:
        payload.exp = datetime.now(timezone.utc) + timedelta(seconds=EXPIRES_SECONDS)
        encoded_jwt = jwt.encode(payload.dict(), AUTH_SECRET, algorithm='HS256')
        return AuthResponse(token=encoded_jwt, expires_in=EXPIRES_SECONDS).dict()

    @staticmethod
    def add_to_blacklist(token: str):
        Blacklist.add_token(token)

    @staticmethod
    def is_blacklisted(token: str) -> bool:
        return Blacklist.is_blacklisted(token)

    @staticmethod
    def verify_token(token: str) -> Dict:
        if TokenService.is_blacklisted(token):
            raise TokenBlacklisted("Token invalidated. Get new one")
        try:
            decoded = jwt.decode(token, AUTH_SECRET, algorithms=['HS256'])
            return AuthPayload(**decoded).dict()
        except jwt.ExpiredSignatureError:
            raise TokenExpired("Token expired. Get new one")
        except jwt.InvalidTokenError:
            raise TokenInvalid("Invalid token")


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
