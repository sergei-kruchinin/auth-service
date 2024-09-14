# auths > routes > __init__.py

from flask import Blueprint
from .auth import register_routes as register_auth_routes
from .front_emu import register_routes as register_front_emu_routes
auth_bp = Blueprint('auth', __name__)
front_emu_bp = Blueprint('front_emu', __name__)


main_bp = Blueprint('main', __name__)


def register_all_routes():
    register_auth_routes(main_bp)
    register_front_emu_routes(main_bp)
