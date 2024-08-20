import base64
import hashlib
import os
from functools import wraps

import requests
from flask import request

from . import app
from .models import Users, Blacklist
from .yandex_html import *


# decorator for token verification
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        authorization_header = request.headers.get('authorization')

        # fix bug where no token
        if authorization_header is None:
            return {'success': False, 'message': 'header not specified'}

        prefix = "Bearer "
        if authorization_header.startswith(prefix):
            token = authorization_header[len(prefix):]
        else:
            return {'success': False, 'message': 'token prefix not supported'}

        verification = Users.auth_verify(token)
        return f(token, verification, *args, **kwargs)

    return decorated


# if invalid json, return json error, not html
@app.errorhandler(400)
def bad_request(error):
    return {'success': False, 'message': 'Invalid JSON sent'}, 400


# if not found
@app.errorhandler(404)
def not_found(error):
    return {'success': False, 'message': 'Resource not found'}, 404


# if invalid method, return json error, not html
@app.errorhandler(405)
def invalid_method(error):
    return {'success': False, 'message': 'Invalid method sent'}, 405


@app.errorhandler(500)
def server_error(error):
    return {'success': False, 'message': 'Server error'}, 500


@app.errorhandler(415)
def invalid_mediatype(error):
    return {'success': False, 'message': 'Unsupported media type'}, 415

# TODO: add HTTP codes to routes' return


# HTML / dummy
@app.route("/", methods=["GET"])
def site_root():
    return '<html><body>hello world</body></html>'


# API Route for checking the user_id and user_secret
@app.route("/auth", methods=["POST"])
def auth():
    # get the user_id and secret from the client application
    json_data = request.get_json()
    if json_data is None:
        return {'success': False, 'message': 'No input data provided'}, 400

    login = json_data.get("login")
    user_secret_input = json_data.get("password")

    # fix bug if no login or password in json
    if login is None or user_secret_input is None:
        return {'success': False, 'message': 'login or password not specified'}

    # the user secret in the database is "hashed" with a one-way hash
    hash_object = hashlib.sha1(bytes(user_secret_input, 'utf-8'))
    hashed_user_secret = hash_object.hexdigest()

    # make a call to the model to authenticate
    authentication = Users.authenticate(login, hashed_user_secret)
    if not authentication:
        return {'success': False}
    else:
        return authentication


# API route for verifying the token passed by API calls
@app.route("/verify", methods=["POST"])
@token_required
def verify(_, verification):
    # verify the token
    return verification

# API Callback to get token and receive data from yandex
@app.route("/auth/yandex/callback", methods=["POST", "GET"])
def auth_yandex_post():

    if request.method == 'POST':
        token = request.json.get('token')
    else:
        # GET
        token = request.args.get('token')
        yandex_code = request.args.get('code')

        if token is None and yandex_code is not None:
            yandex_url = 'https://oauth.yandex.ru/token'
            client_id = os.getenv('YANDEX_ID')
            client_secret = os.getenv('YANDEX_SECRET')
            client_id_sec = f'{client_id}:{client_secret}'
            client_id_sec_base64_encoded = base64.b64encode(client_id_sec.encode()).decode()
            headers = {'Authorization': f'Basic {client_id_sec_base64_encoded}'}
            params = {'grant_type': 'authorization_code', 'code': yandex_code}
            response = requests.post(yandex_url, headers=headers, data=params)
            try:
                json_response = response.json()
            except requests.exceptions.JSONDecodeError:
                return {'error': 'Response could not be decoded as JSON.'}, 400

            if response.status_code == 200:
                token = json_response.get('access_token')
            else:
                return {'error': 'Unable to retrieve access_token'}, 400

    headers = {'Authorization': f'OAuth {token}'}
    yandex_url = 'https://login.yandex.ru/info'

    # Request to Yandex API to get user info
    response = requests.get(yandex_url, headers=headers)
    if response.status_code == 200:
        user_info = response.json()
        oa_id = user_info.get('id')
        # yandex_login = user_info.get('login')
        # user_sex = user_info.get('sex')
        # user_birthday = user_info.get('birthday')

        # user_email = user_info.get('default_email')
        # user_full_name = user_info.get('real_name')
        first_name = user_info.get('first_name')
        last_name = user_info.get('last_name')
        source = "yandex"
        login = f"{source}:{oa_id}"
        hashed_user_secret = None
        is_admin = False

        # add to our database
        update_response = Users.create_or_update(login, first_name, last_name, hashed_user_secret, is_admin, source,
                                                 oa_id)
        if update_response:
            authentication = Users.authenticate_oauth(login)
            if not authentication:
                return {'success': False}
            else:
                return authentication, 200

        else:
            return {'success': False, 'message': 'Could not update -- probably some fields are missing'}, 400
    else:
        return {'success': False, 'message': 'Access Denied'}, 401
        # END TO DO


    return {'error': 'Unable to retrieve user data'}, 400


# Frontend imitation for testing Yandex OAuth 2.0
@app.route("/auth/yandex.html", methods=["GET"])
def auth_yandex_html():
    yandex_id = os.getenv('YANDEX_ID')
    api_domain = os.getenv('API_DOMAIN')
    redirect_uri = f"https://{api_domain}/auth/yandex/callback.html"
    callback_uri = f"https://{api_domain}/auth/yandex/callback"
    return auth_yandex_html_code(yandex_id, api_domain, redirect_uri, callback_uri)


# Yandex OAuth 2.0 Authorization by Code support almost without frontend (only for yandex form if it's needed)
def generate_yandex_iframe_uri():
    yandex_id = os.getenv('YANDEX_ID')
    iframe_uri = f'https://oauth.yandex.ru/authorize?response_type=code&client_id={yandex_id}'
    return iframe_uri


# API route returns URI for yandex page for authorization -- for REST API client
@app.route("/auth/yandex/bycode", methods=["GET"])
def auth_yandex_bycode():
    iframe_uri = generate_yandex_iframe_uri()
    return {'iframe_uri': iframe_uri}


# HTML sugar for easy testing
@app.route("/auth/yandex/bycode.html", methods=["GET"])
def auth_yandex_bycode_html():
    iframe_uri = generate_yandex_iframe_uri()
    return f'<a href="{iframe_uri}">{iframe_uri}</a>'


# Frontend imitation helper page (to get token from yandex) and send to frontend auth_yandex_html page
@app.route("/auth/yandex/callback.html", methods=["GET"])
def auth_yandex_callback_html():
    api_domain = os.getenv('API_DOMAIN')
    callback_uri = f"https://{api_domain}/auth/yandex/callback.html"
    return auth_yandex_callback_html_code(callback_uri)





# API route for token revocation
@app.route("/logout", methods=["POST"])
@token_required
def logout(token, verification):
    if verification.get('success') is False:  # if verifications return json data success 'll be Null
        message = verification.get('message')
        status = True
        # if already no valid nothing to do
    else:  # Auth succeed so adding to blacklist
        Blacklist.add_token(token)  # now it doesn't return True or False
        status = True
        message = 'Adding to blacklist '
    return {'success': status, 'message': message}


# TODO make a logout from all devices
# TODO is_system and source and source_id usage in routes and methods


# API route to create the new user
@app.route("/users", methods=["POST"])
@token_required
def users_create(_, verification):
    if verification.get("is_admin"):
        # get the client_id and secret from the client application
        json_data = request.get_json()
        login = json_data.get("login")
        first_name = json_data.get("first_name")
        last_name = json_data.get("last_name")
        # compability
        if first_name == '' or first_name is None:
            first_name = login
        if last_name == '' or last_name is None:
            last_name = 'system'

        user_secret_input = json_data.get("password")
        is_admin = json_data.get("is_admin")
        if is_admin == '' or is_admin is None:
            is_admin = False

        # the user secret in the database is "hashed" with a one-way hash
        hash_object = hashlib.sha1(bytes(user_secret_input, 'utf-8'))
        hashed_user_secret = hash_object.hexdigest()

        # make a call to the model to create user
        create_response = Users.create(login, first_name, last_name, hashed_user_secret, is_admin)
        if create_response:
            return {'success': create_response}, 201
        else:
            return {'success': False, 'message': 'Could not create -- probably some fields are missings'}, 400
    else:
        return {'success': False, 'message': 'Access Denied'}, 401



# Route only for testing method
# Delete after pdating /auth/yandex/callback and adding using this method there
@app.route("/users_update", methods=["POST"])
@token_required
def users_update(_, verification):
    if verification.get("is_admin"):
        # get the data from the client application
        json_data = request.get_json()
        login = json_data.get("login")
        first_name = json_data.get("first_name")
        last_name = json_data.get("last_name")

        if first_name == '' or first_name is None:
            first_name = login
        if last_name == '' or last_name is None:
            last_name = 'system'

        user_secret_input = json_data.get("password")
        is_admin = json_data.get("is_admin")
        if is_admin == '' or is_admin is None:
            is_admin = False

        # the user secret in the database is "hashed" with a one-way hash
        hash_object = hashlib.sha1(bytes(user_secret_input, 'utf-8'))
        hashed_user_secret = hash_object.hexdigest()

        # make a call to the model to update user
        update_response = Users.create_or_update(login, first_name, last_name, hashed_user_secret, is_admin)
        if update_response:
            return {'success': True}, 200
        else:
            return {'success': False, 'message': 'Could not update -- probably some fields are missing'}, 400
    else:
        return {'success': False, 'message': 'Access Denied'}, 401


# DUMMY for API route to delete user (if is_admin)
@app.route("/users", methods=["DELETE"])
@token_required
def users_delete():
    # not yet implemented
    return {'success': False}


# API route to get users list
@app.route("/users", methods=["GET"])
@token_required
def users_list(_, verification):
    if verification.get("is_admin"):
        return Users.list()
    else:
        return {'success': False, 'message': 'Access Denied'}
