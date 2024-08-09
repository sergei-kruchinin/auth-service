from . import app
from flask import request
import json
import hashlib
from .models import Users, Blacklist
from functools import wraps


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        authorization_header = request.headers.get('authorization')

        # fix bug where no token
        if authorization_header is None:
            return {'success': False, 'message': 'header not specified'}
        token = authorization_header.replace("Bearer ", "")
        verification = Users.auth_verify(token)
        return f(token, verification, *args, **kwargs)

    return decorated


@app.errorhandler(400)
def bad_request():
    return {'success': False, 'message': 'Invalid JSON sent'}, 400


@app.route("/hello", methods=["POST"])
def hello():
    # TODO: remove this function -- it was just for me
    # TODO: before: make the wellcome function. From jwt token reads th info about user and is_admin status

    json_data = request.get_json()
    user_name = json_data.get("user_name")
    return {'success': True, 'user_name': user_name}


# API Route for checking the client_id and client_secret
@app.route("/auth", methods=["POST"])
def auth():
    # get the user_id and secret from the client application
    json_data = request.get_json()
    user_name = json_data.get("login")
    user_secret_input = json_data.get("password")

    # fix bug if no login or password in json
    if user_name is None or user_secret_input is None:
        return {'success': False, 'message': 'login or password not specified'}

    # the user secret in the database is "hashed" with a one-way hash
    hash_object = hashlib.sha1(bytes(user_secret_input, 'utf-8'))
    hashed_user_secret = hash_object.hexdigest()

    # make a call to the model to authenticate
    authentication = Users.authenticate(user_name, hashed_user_secret)
    if not authentication:
        return {'success': False}
    else:
        return json.dumps(authentication)


# API route for verifying the token passed by API calls
@app.route("/verify", methods=["POST"])
@token_required
def verify(_, verification):
    # verify the token 
    return verification


@app.route("/logout", methods=["POST"])
@token_required
def logout(token, verification):
    # TODO: Remove message (it was just for me)
    if verification.get('success') is False:  # if verifications return json data success 'll be Null
        message = verification.get('message')
        status = True
        # if already no valid nothing to do
    else:  # Auth succeed so adding to blacklist
        Blacklist.add_token(token)  # now it doesn't return True or False
        status = True
        message = 'Adding to blacklist '
    return {'success': status, 'message': message}


@app.route("/users", methods=["POST"])
@token_required
def users_create(_, verification):
    if verification.get("is_admin"):
        # get the client_id and secret from the client application
        json_data = request.get_json()
        user_name = json_data.get("login")
        user_secret_input = json_data.get("password")
        is_admin = json_data.get("is_admin")

        # the user secret in the database is "hashed" with a one-way hash
        hash_object = hashlib.sha1(bytes(user_secret_input, 'utf-8'))
        hashed_user_secret = hash_object.hexdigest()

        # make a call to the model to authenticate
        create_response = Users.create(user_name, hashed_user_secret, is_admin)
        return {'success': create_response}
    else:
        return {'success': False, 'message': 'Access Denied'}


@app.route("/users", methods=["DELETE"])
@token_required
def users_delete():
    # not yet implemented
    return {'success': False}


@app.route("/users", methods=["GET"])
@token_required
def users_list(_, verification):
    if verification.get("is_admin"):
        return Users.list()
    else:
        return {'success': False, 'message': 'Access Denied'}
