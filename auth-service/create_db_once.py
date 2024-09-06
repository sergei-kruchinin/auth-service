from auths import db, app
from auths.models import Users
from auths.schemas import OauthUserCreateSchema

with app.app_context():
    db.drop_all()  # only for debug
    db.create_all()
    user_data = OauthUserCreateSchema(
        login='admin',
        first_name='admin',
        last_name='system',
        password='password',
        is_admin=True,
        source='manual',
        oa_id=None
    )
    Users.create_with_check(user_data.dict())

    print(Users.query.all())
