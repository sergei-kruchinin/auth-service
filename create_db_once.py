# create_db_once.py

from sqlalchemy.orm import sessionmaker, Session
from core.models.base import init_db, engine, Base
from core.models.user import User
from core.schemas import ManualUserCreateSchema


def create_db_once():
    session_local = sessionmaker(bind=engine)
    Base.metadata.drop_all(bind=engine)  # for debug only
    init_db()

    db: Session = session_local()

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


if __name__ == "__main__":
    create_db_once()
