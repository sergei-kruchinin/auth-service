from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import os


# instantiate the Flask app.
app = Flask(__name__)

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = ''
# app.config["JWT_ALGORITHM"] = "HS256"

db = SQLAlchemy(app)



