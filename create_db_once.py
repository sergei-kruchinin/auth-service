# create_db_once.py

from flask_app import create_app
from core import init_db, db_session, engine
from core.models import User, Base
from core.schemas import ManualUserCreateSchema

app = create_app()

with app.app_context():
    Base.metadata.drop_all(bind=engine)  # for debug only
    init_db()
    db_session.remove()
    db_session.configure(bind=engine)
    user_data = ManualUserCreateSchema(
        login='admin',
        first_name='admin',
        last_name='system',
        password='password',
        is_admin=True,
        source='manual',
        oa_id=None
    )
    User.create_with_check(db_session, user_data)

    print(db_session.query(User).all())
