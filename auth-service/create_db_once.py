from auths import db, app
from auths.models import Users

with app.app_context():
    db.drop_all()  # only for debug
    db.create_all()
    user_password = 'password'
    Users.create(login='admin', first_name='admin', last_name='system', password=user_password, is_admin=True)
    print(Users.query.all())
