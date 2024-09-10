# auths > init.py

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import os
from dotenv import load_dotenv
from .error_handlers import register_error_handlers
from .config.logging import setup_logging

# Load .env file
load_dotenv()

# instantiate the Flask app
db = SQLAlchemy()


def create_app():
    setup_logging()  # Инициализация логирования

    app = Flask(__name__)
    app = register_error_handlers(app)

    basedir = os.path.abspath(os.path.dirname(__file__))
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'users.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')

    db.init_app(app)

    with app.app_context():
        from .routes import auth_bp
        app.register_blueprint(auth_bp, url_prefix='/')

    return app
