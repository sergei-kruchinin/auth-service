import base64
from functools import wraps

import requests
from flask import request

from . import app
from .models import *
from .yandex_html import *


class CustomValidationError(Exception):
    pass

class HeaderNotSpecifiedError(CustomValidationError):
    pass


class TokenPrefixNotSupportedError(CustomValidationError):
    pass


class AdminRequiredError(Exception):
    pass


class NoDataProvided(Exception):
    """Raised when there is no input data provided."""
    pass


class InsufficientData(AuthenticationError):
    """Raised when there is insufficient data (login or password missing)."""
    pass


class OAuthServerError(Exception):
    pass


class OAuthTokenRetrievalError(OAuthServerError):
    pass


class OAuthUserDataRetrievalError(OAuthServerError):
    pass





# Flask errorhandlers

# if invalid json, return json error, not html
@app.errorhandler(400)
def bad_request(_):
    return {'success': False, 'message': 'Invalid JSON sent'}, 400


# if not found
@app.errorhandler(404)
def not_found(_):
    return {'success': False, 'message': 'Resource not found'}, 404


# if invalid method, return json error, not html
@app.errorhandler(405)
def invalid_method(_):
    return {'success': False, 'message': 'Invalid method sent'}, 405


@app.errorhandler(500)
def server_error(_):
    return {'success': False, 'message': 'Server error'}, 500


@app.errorhandler(415)
def invalid_mediatype(_):
    return {'success': False, 'message': 'Unsupported media type'}, 415


# My Error handlers
@app.errorhandler(AuthenticationError)
def handle_auth_error(e):
    return {'message': str(e)}, 401


@app.errorhandler(CustomValidationError)
def handle_validation_error(e):
    return {'message': str(e)}, 401 # or 400?


@app.errorhandler(AdminRequiredError)
def handle_admin_required_error(e):
    return {'message': str(e)}, 403


@app.errorhandler(DatabaseError)
def handle_database_error(e):
    return {'message': str(e)}, 500  # 500 is the status code for Internal Server Error


@app.errorhandler(NoDataProvided)
def handle_no_data_provided(e):
    return {'success': False, 'message': str(e)}, 400


@app.errorhandler(OAuthServerError)
def oauth_server_error_occurred(e):
    return {'error': str(e)}, 503



# decorator for token verification
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        authorization_header = request.headers.get('authorization')

        # raise exception where no token
        if authorization_header is None:
            raise HeaderNotSpecifiedError('header not specified')

        prefix = "Bearer "
        if not authorization_header.startswith(prefix):
            raise TokenPrefixNotSupportedError('token prefix not supported')

        token = authorization_header[len(prefix):]
        verification = Users.auth_verify(token)
        return f(token, verification, *args, **kwargs)

    return decorated


# HTML / dummy
@app.route("/", methods=["GET"])
def site_root():
    return '<html><body>hello world</body></html>'


# API Route for checking login and password
@app.route("/auth", methods=["POST"])
def auth():
    # get the user_id and secret from the client application
    json_data = request.get_json()
    if json_data is None:
        raise NoDataProvided('No input data provided')
    try:
        auth_request = AuthRequest(**json_data)
    except ValidationError as e:
        raise InsufficientData('login or password not specified') from e

    # If authentication fails, this will raise an AuthenticationError
    # which will be caught by the error handler and a proper JSON response will be formed.
    authentication = Users.authenticate(auth_request.login, auth_request.password)

    return authentication, 200


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
                raise OAuthServerError('Yandex response could not be decoded as JSON.')

            if response.status_code == 200:
                token = json_response.get('access_token')
            else:
                raise OAuthTokenRetrievalError('Unable to retrieve access_token')


    headers = {'Authorization': f'OAuth {token}'}
    yandex_url = 'https://login.yandex.ru/info'

    # Request to Yandex API to get user info
    response = requests.get(yandex_url, headers=headers)
    if response.status_code != 200:
        raise OAuthUserDataRetrievalError('Unable to retrieve user data')

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
    password = None
    is_admin = False
    # add to our database (or update)
    Users.create_or_update(login, first_name, last_name, password, is_admin, source, oa_id)
    authentication = Users.authenticate_oauth(login)
    return authentication, 200



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
@app.route("/auth/yandex/by_code", methods=["GET"])
def auth_yandex_by_code():
    iframe_uri = generate_yandex_iframe_uri()
    return {'iframe_uri': iframe_uri}


# HTML sugar for easy testing
@app.route("/auth/yandex/by_code.html", methods=["GET"])
def auth_yandex_by_code_html():
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


# Create system user
@app.route("/users", methods=["POST"])
@token_required
def users_create(_, verification):
    if not verification.get("is_admin"):
        raise AdminRequiredError("Access Denied")

    json_data = request.get_json()
    if json_data is None:
        raise CustomValidationError("No input data provided")

    login = json_data.get("login")
    first_name = json_data.get("first_name", login)
    last_name = json_data.get("last_name", "system")
    password = json_data.get("password")
    is_admin = bool(json_data.get("is_admin"))

    if not all([login, first_name, last_name, password]):
        raise CustomValidationError("Missing fields in data")

    Users.create(login, first_name, last_name, password, is_admin)

    return {'success': True}, 201


# Route only for testing method
# Delete after updating /auth/yandex/callback and adding using this method there
@app.route("/users_update", methods=["POST"])
@token_required
def users_update(_, verification):
    if not verification.get("is_admin"):
        raise AdminRequiredError("Access Denied")

    json_data = request.get_json()
    if json_data is None:
        raise CustomValidationError("No input data provided")

    login = json_data.get("login")
    first_name = json_data.get("first_name", login)
    last_name = json_data.get("last_name", "system")
    password = json_data.get("password")
    is_admin = bool(json_data.get("is_admin"))
    # source = json_data.get("source")
    # oa_id = json_data.get("oa_id")

    if not all([login, first_name, last_name, password]):
        raise CustomValidationError("Missing fields in data")

    Users.create_or_update(login, first_name, last_name, password, is_admin)

    return {'success':  True}, 200



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
        raise AdminRequiredError('Access Denied')