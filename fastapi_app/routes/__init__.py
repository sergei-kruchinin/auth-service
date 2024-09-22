# fastapi_app > routes > __init__.py

from fastapi import APIRouter
from .auth import register_routes as register_auth_routes
from .front_emu import register_routes as register_front_emu_routes

main_router = APIRouter()


def register_all_routes(router: APIRouter):
    register_auth_routes(router)
    register_front_emu_routes(router)

    print(f"Routes registered in main_router: {[route.path for route in router.routes if hasattr(route, 'path')]}")
