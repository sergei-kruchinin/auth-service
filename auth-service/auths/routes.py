import base64
import hashlib
import json
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
        token = authorization_header.replace("Bearer ", "")
        verification = Users.auth_verify(token)
        return f(token, verification, *args, **kwargs)

    return decorated


# if invalid json, return json error, not html
@app.errorhandler(400)
def bad_request():
    return {'success': False, 'message': 'Invalid JSON sent'}, 400

# TODO: add HTTP codes to routes' return


# HTML / dummy
@app.route("/", methods=["GET"])
def site_root():
    return '<html><body>hello world</body></html>'




# API Callback to get token and recieve data from yandex
@app.route("/auth/yandex/callback", methods=["POST","GET"])
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
        user_email = user_info.get('default_email')
        user_full_name = user_info.get('real_name')
        # TO DO -- add info to database and return JWT-token for auth, i.e. in POSTMAN
        return {'email': user_email, 'full_name': user_full_name}, 200

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
    iframe_uri=f'https://oauth.yandex.ru/authorize?response_type=code&client_id={yandex_id}'
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


# API Route for checking the user_id and user_secret
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


# API route to create the new user
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

        # make a call to the model to create user
        create_response = Users.create(user_name, hashed_user_secret, is_admin)
        return {'success': create_response}
    else:
        return {'success': False, 'message': 'Access Denied'}


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
