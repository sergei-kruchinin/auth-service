from flask import Blueprint
from .routes import register_routes

auth_bp = Blueprint('auth', __name__)
register_routes(auth_bp)
