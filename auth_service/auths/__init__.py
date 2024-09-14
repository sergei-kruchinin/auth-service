# auths > __init__.py

from flask import Flask
import os
from dotenv import load_dotenv

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session

from .error_handlers import register_error_handlers
from .logging_conf import setup_logging

# Load .env file
load_dotenv()

# Database setup
basedir = os.path.abspath(os.path.dirname(__file__))
Base = declarative_base()
engine = create_engine('sqlite:///' + os.path.join(basedir, 'users.db'))
db_session = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))


def create_app():
    setup_logging()  # Инициализация логирования

    app = Flask(__name__)
    app = register_error_handlers(app)

    from .routes import register_all_routes, main_bp
    register_all_routes()
    app.register_blueprint(main_bp, url_prefix='/')
    return app


def init_db():
    import auth_service.auths.models
    Base.metadata.create_all(bind=engine)
