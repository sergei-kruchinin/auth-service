# flask_app > __init__.py

from flask import Flask

from dotenv import load_dotenv

from flask_app.error_handlers import register_error_handlers
from config.logging_conf import setup_logging

# Load .env file
load_dotenv()


def create_app():
    setup_logging()

    app = Flask(__name__, template_folder='../templates')
    app = register_error_handlers(app)

    from flask_app.routes import register_all_routes, main_bp
    register_all_routes()
    app.register_blueprint(main_bp, url_prefix='/')
    return app
