# create_db_once.py

from flask_app import create_app
from sqlalchemy.orm import sessionmaker, Session
from core.models.base import init_db, engine, Base
from core.models.user import User
from core.schemas import ManualUserCreateSchema

app = create_app()

SessionLocal = sessionmaker(bind=engine)

with app.app_context():
    Base.metadata.drop_all(bind=engine)  # for debug only
    init_db()

    db: Session = SessionLocal()

    try:
        user_data = ManualUserCreateSchema(
            login='admin',
            first_name='admin',
            last_name='system',
            password='password',
            is_admin=True,
            source='manual',
            oa_id=None
        )
        User.create_with_check(db, user_data)

        users = db.query(User).all()
        for user in users:
            print(user)

        db.commit()
    except Exception as e:
        db.rollback()
        print(f"Error occurred: {e}")
    finally:
        db.close()
