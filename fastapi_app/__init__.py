# fastapi_app > __init__.py

from fastapi import FastAPI
from dotenv import load_dotenv

print('Загружаем переменные окружения')
load_dotenv()

from config.logging_conf import setup_logging
from fastapi_app.error_handlers import register_error_handlers
from fastapi_app.routes import register_all_routes, main_router



def create_app():
    setup_logging()

    app = FastAPI()

    register_error_handlers(app)

    register_all_routes(main_router)
    app.include_router(main_router)

    return app


def print_routes(app):
    routes = [route for route in app.routes if hasattr(route, "path")]
    for route in routes:
        print(f"Registered route: {route.path}")


