# create_db_once.py

from auths import create_app, db
from auths.models import Users
from auths.schemas import UserCreateInputSchema

app = create_app()

with app.app_context():
    db.drop_all()  # only for debug
    db.create_all()
    user_data = UserCreateInputSchema(
        login='admin',
        first_name='admin',
        last_name='system',
        password='password',
        is_admin=True,
        source='manual',
        oa_id=None
    )
    Users.create_with_check(user_data)

    print(Users.query.all())