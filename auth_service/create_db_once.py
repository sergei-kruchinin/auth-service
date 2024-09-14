# create_db_once.py

from auths import create_app, init_db, db_session, engine
from auths.models import User, Base
from auths.schemas import UserCreateInputSchema

app = create_app()

with app.app_context():
    Base.metadata.drop_all(bind=engine)  # for debug only
    init_db()
    db_session.remove()
    db_session.configure(bind=engine)
    user_data = UserCreateInputSchema(
        login='admin',
        first_name='admin',
        last_name='system',
        password='password',
        is_admin=True,
        source='manual',
        oa_id=None
    )
    User.create_with_check(user_data)

    print(db_session.query(User).all())
