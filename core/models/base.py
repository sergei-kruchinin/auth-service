# core/models/base.py

import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session

# Database setup
basedir = os.path.abspath(os.path.dirname(__file__))
Base = declarative_base()
engine = create_engine('sqlite:///' + os.path.join(basedir, 'users.db'))
db_session = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))


def get_db():
    db = db_session()
    try:
        yield db
    finally:
        db.close()


def init_db():
    from core.models.user import User
    from core.models.user_session import UserSession
    Base.metadata.create_all(bind=engine)
