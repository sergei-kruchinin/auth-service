from auths import db, app
from auths.models import Users
from auths.schemas import UserCreateInputSchema

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
