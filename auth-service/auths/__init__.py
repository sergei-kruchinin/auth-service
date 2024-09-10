from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import os
from dotenv import load_dotenv
# from flask_migrate import Migrate
from .error_handlers import register_error_handlers
import logging
from .config_logging import setup_logging
setup_logging()


# Load .env file
load_dotenv()

# instantiate the Flask app.
app = Flask(__name__)
app = register_error_handlers(app)

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = ''
# app.config["JWT_ALGORITHM"] = "HS256"

db = SQLAlchemy(app)

# migrate = Migrate(app, db)
