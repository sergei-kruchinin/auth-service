from auths import db, app
from auths.models import Users, Blacklist
import hashlib

with app.app_context():
    db.create_all()
    user_password = 'password'
    hash_object = hashlib.sha1(bytes(user_password, 'utf-8'))
    hashed_user_secret = hash_object.hexdigest()
    Users.create(login='admin', first_name='admin', last_name='system', secret=hashed_user_secret, is_admin=True)
    print(Users.query.all())
