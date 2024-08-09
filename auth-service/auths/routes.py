from . import app
from flask import request
import json
import hashlib
from .models import Users, Blacklist


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
def verify():
    # verify the token 
    authorization_header = request.headers.get('authorization')

    # fix bug where no token
    if authorization_header is None:
        return {'success': False, 'message': 'header not specified'}
    token = authorization_header.replace("Bearer ", "")
    verification = Users.auth_verify(token)
    return verification


@app.route("/logout", methods=["POST"])
def logout():
    # TODO: Remove message (it was just for me)

    # Unobviously we don't need to add token to blacklist if it's already present
    # # (by the way may be it'll be better to Blacklist.add_token better to check it?... hm
    # Checking authorization
    authorization_header = request.headers.get('authorization')
    # fix bug where no token
    if authorization_header is None:
        return {'success': False, 'message': 'header not specified'}

    token = authorization_header.replace("Bearer ", "")
    # checking correctly authenticated?
    verification = Users.auth_verify(token)
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
def users_create():
    # verify the token
    authorization_header = request.headers.get('authorization')
    if authorization_header is None:
        return {'success': False, 'message': 'header not specified'}

    token = authorization_header.replace("Bearer ", "")
    verification = Users.auth_verify(token)

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
def users_delete():
    # not yet implemented
    return {'success': False}


@app.route("/users", methods=["GET"])
def users_list():
    # verify the token
    authorization_header = request.headers.get('authorization')
    if authorization_header is None:
        return {'success': False, 'message': 'header not specified'}

    token = authorization_header.replace("Bearer ", "")
    verification = Users.auth_verify(token)
    if verification.get("is_admin"):
        return Users.list()
    else:
        return {'success': False, 'message': 'Access Denied'}
