import base64
from functools import wraps

import requests
from requests.exceptions import SSLError, ConnectionError

from flask import request

from . import app
from .models import *
from .yandex_html import *
from .schemas import AuthRequest, UserCreateSchema
from pydantic import ValidationError


class CustomValidationError(Exception):
    pass


class HeaderNotSpecifiedError(CustomValidationError):
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


# Flask error handlers
@app.errorhandler(400)
def bad_request(_):
    """if invalid json, return json error, not html"""
    return {'success': False, 'message': 'Invalid JSON sent'}, 400



@app.errorhandler(404)
def not_found(_):
    """if not found route"""
    return {'success': False, 'message': 'Resource not found'}, 404


@app.errorhandler(ValidationError)
def handle_pydantic_validation_error(e):
    return {'message': str(e)}, 400


@app.errorhandler(405)
def invalid_method(_):
    """if invalid method, return json error, not html"""
    return {'success': False, 'message': 'Invalid method sent'}, 405


@app.errorhandler(500)
def server_error(_):
    return {'success': False, 'message': 'Server error'}, 500


@app.errorhandler(415)
def invalid_mediatype(_):
    return {'success': False, 'message': 'Unsupported media type'}, 415


@app.errorhandler(Exception)
def handle_general_error(e):
    return {'success': False, 'message': 'An unexpected error occurred: ' + str(e)}, 500


@app.errorhandler(SSLError)
def handle_ssl_error(_):
    return {'success': False, 'message': 'SSL error occurred, certificate verification failed'}, 503


@app.errorhandler(ConnectionError)
def handle_connection_error(_):
    return {'success': False, 'message': 'Connection error occurred, please try again later'}, 503


# My Error handlers
@app.errorhandler(AuthenticationError)
def handle_auth_error(e):
    return {'message': str(e)}, 401


@app.errorhandler(CustomValidationError)
def handle_validation_error(e):
    return {'message': str(e)}, 400  # or 401?


@app.errorhandler(AdminRequiredError)
def handle_admin_required_error(e):
    return {'message': str(e)}, 403


@app.errorhandler(DatabaseError)
def handle_database_error(e):
    return {'message': str(e)}, 500  # Internal Server Error


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
        prefix = 'Bearer '
        if not authorization_header or not authorization_header.startswith(prefix):
            raise HeaderNotSpecifiedError('Header not specified or prefix not supported.')

        token = authorization_header[len(prefix):]
        try:
            verification = Users.auth_verify(token)
        except TokenBlacklisted as e:
            raise TokenBlacklisted("Token invalidated. Get new one") from e
        except TokenExpired as e:
            raise TokenExpired("Token expired. Get new one") from e
        except TokenInvalid as e:
            raise TokenInvalid("Invalid token") from e

        return f(token, verification, *args, **kwargs)

    return decorated


@app.route("/", methods=["GET"])
def site_root():
    """
    Root route for the application (Temporary/Dummy)

    Method: GET

    Returns:
    200: HTML page with "hello world".
    """
    return '<html><body>hello world</body></html>'


@app.route("/auth", methods=["POST"])
def auth():
    """
    Route for authenticating a user.

    Request body:
    {
        "login": "<login>",
        "password": "<password>"
    }

    Returns:
    200: {'token': '<token>', 'expires_in': <expires_in>}
    400: If no data is provided
    401: For invalid login/password
    """

    # get the user_id and secret from the client application
    json_data = request.get_json()
    if not json_data:
        raise NoDataProvided('No input data provided')
    try:
        auth_request = AuthRequest(**json_data)
    except ValidationError as e:
        raise InsufficientData('login or password not specified') from e

    # If authentication fails, this will raise an AuthenticationError
    # which will be caught by the error handler and a proper JSON response will be forme
    try:
        authentication = Users.authenticate(auth_request.login, auth_request.password)
    except AuthenticationError as e:
        raise AuthenticationError('Invalid login or password') from e

    return authentication, 200


@app.route("/verify", methods=["POST"])
@token_required
def verify(_, verification):
    """
    Route for verifying an authentication token.

    Method: POST

    Headers:
    - Authorization: Bearer <token>

    Returns:
    200: JSON containing verification status
    401: For invalid or expired tokens
    """
    return verification


@app.route("/auth/yandex/callback", methods=["POST", "GET"])
def auth_yandex_callback():
    """
    Route for handling Yandex OAuth callback.

    Methods: POST, GET

    Request parameters:
    - token (POST, JSON): The OAuth token
    - code (GET, query parameter): The authorization code from Yandex

    Returns:
    200: JSON containing authentication token
    503: If there's an OAuth or user data retrieval error
    """

    def get_token_from_code(yandex_code):
        yandex_url = 'https://oauth.yandex.ru/token'
        client_id = os.getenv('YANDEX_ID')
        client_secret = os.getenv('YANDEX_SECRET')

        client_id_sec = f'{client_id}:{client_secret}'
        client_id_sec_base64_encoded = base64.b64encode(client_id_sec.encode()).decode()
        headers = {'Authorization': f'Basic {client_id_sec_base64_encoded}'}
        params = {'grant_type': 'authorization_code', 'code': yandex_code}

        response = requests.post(yandex_url, headers=headers, data=params)
        response.raise_for_status()
        return response.json().get('access_token')

    def get_user_info(token):
        headers = {'Authorization': f'OAuth {token}'}
        yandex_url = 'https://login.yandex.ru/info'

        response = requests.get(yandex_url, headers=headers)
        response.raise_for_status()
        return response.json()

    if request.method == 'POST':
        token = request.json.get('token')
    else:  # GET
        token = request.args.get('token')
        yandex_code = request.args.get('code')

        if token is None and yandex_code is not None:
            try:
                token = get_token_from_code(yandex_code)
            except requests.exceptions.RequestException as e:
                raise OAuthServerError(f'Yandex OAuth error: {str(e)}')

    if token is None:
        raise OAuthServerError('No token or authorization code provided')

    try:
        user_info = get_user_info(token)
    except requests.exceptions.RequestException as e:
        raise OAuthUserDataRetrievalError(f'Unable to retrieve user data: {str(e)}')
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
    try:
        Users.create_or_update(login, first_name, last_name, password, is_admin, source, oa_id)
        authentication = Users.authenticate_oauth(login)
    except DatabaseError as e:
        raise DatabaseError("There was an error while syncing the user from yandex") from e

    return authentication, 200


def generate_yandex_iframe_uri():
    yandex_id = os.getenv('YANDEX_ID')
    iframe_uri = f'https://oauth.yandex.ru/authorize?response_type=code&client_id={yandex_id}'
    return iframe_uri


@app.route("/auth/yandex/by_code", methods=["GET"])
def auth_yandex_by_code():
    """
    Route for generating Yandex OAuth authorization URI.

    Method: GET

    Returns:
    200: JSON containing the iframe URI
    """
    iframe_uri = generate_yandex_iframe_uri()
    return {'iframe_uri': iframe_uri}



@app.route("/logout", methods=["POST"])
@token_required
def logout(token, verification):
    """
    Route for logging out a user and invalidating the token.

    Method: POST

    Headers:
    - Authorization: Bearer <token>

    Returns:
    200: {'success': True, 'message': <message>}
    """
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
# TODO make a list of login devices, needed it for logout
# TODO is_system and source and source_id usage in routes and methods


@app.route("/users", methods=["POST"])
@token_required
def users_create(_, verification):
    """
    Route for creating a new user (admin only).

    Method: POST

    Headers:
    - Authorization: Bearer <admin_token>

    Request body (JSON):
    {
        "login": "<login>",
        "first_name": "<first_name>",
        "last_name": "<last_name>",
        "password": "<password>",
        "is_admin": <true/false>
        "source": "<yandex/manual>",
        "oa_id" : <yandex_id>"
    }

    Returns:
    201: {'success': True}
    400: If input data is invalid
    403: If user is not an admin
    500: If there's an error creating the user
    """
    if not verification.get("is_admin"):
        raise AdminRequiredError("Access Denied")

    json_data = request.get_json()
    if not json_data:
        raise CustomValidationError("No input data provided")
    try:
        user_data = UserCreateSchema(**json_data)
    except ValidationError as e:
        raise CustomValidationError(str(e))

    try:
        Users.create(
            login=user_data.login,
            first_name=user_data.first_name,
            last_name=user_data.last_name,
            password=user_data.password,
            is_admin=user_data.is_admin,
            source=user_data.source,
            oa_id=user_data.oa_id
        )
    except DatabaseError as e:
        raise DatabaseError("There was an error while creating a user") from e

    return {'success': True}, 201


@app.route("/users_update", methods=["POST"])
@token_required
def users_update(_, verification):
    """
    Route for updating user data (admin only).
    Only for testing method create_or_update (it's for /auth/yandex/callback) not for regular usage.
    It should be different method PUT /users for data update and PATCH /users for password update
    Should be deleted in future

    Method: POST

    Headers:
    - Authorization: Bearer <admin_token>

    Request body (JSON):
    {
     "login": "<login>",
     "first_name": "<first_name>",
     "last_name": "<last_name>",
     "password": "<password>",
     "is_admin": <true/false>,
     "source": "<yandex/manual>",
     "oa_id" : <yandex_id>"


     Returns:
     200: {'success': True}
     400: If input data is invalid
     403: If user is not an admin
     500: If there's an error updating the user
     """
    if not verification.get("is_admin"):
        raise AdminRequiredError("Access Denied")

    json_data = request.get_json()
    if not json_data:
        raise CustomValidationError("No input data provided")
    try:
        user_data = UserCreateSchema(**json_data)
    except ValidationError as e:
        raise CustomValidationError(str(e))

    try:
        Users.create_or_update(
            login=user_data.login,
            first_name=user_data.first_name,
            last_name=user_data.last_name,
            password=user_data.password,
            is_admin=user_data.is_admin,
            source=user_data.source,
            oa_id=user_data.oa_id
        )
    except DatabaseError as e:
        raise DatabaseError("There was an error while creating a user") from e

    return {'success':  True}, 200


@app.route("/users", methods=["DELETE"])
@token_required
def users_delete():
    """
    Route for deleting a user (if is_admin): not yet implemented.

    Method: DELETE

    Headers:
    - Authorization: Bearer <admin_token>

    Returns:
    501: {'success': False}
    """
    return {'success': False}


@app.route("/users", methods=["GET"])
@token_required
def users_list(_, verification):
    """
    Route for retrieving the list of users (admin only).

    Method: GET

    Headers:
    - Authorization: Bearer <admin_token>

    Returns:
    200: JSON containing the list of users
    403: If user is not an admin
    500: If there's an error retrieving the list
    """
    if not verification.get("is_admin"):
        raise AdminRequiredError('Access Denied')
    try:
        users_list_json = Users.list()
    except DatabaseError as e:
        raise DatabaseError("There was an error while retrieving the users list") from e

    return users_list_json


# Frontend routes for testing Yandex OAuth 2.0
@app.route("/auth/yandex/by_code.html", methods=["GET"])
def auth_yandex_by_code_html():
    """
    Route for displaying the link to Yandex OAuth authorization page.

    Method: GET

    Returns:
    200: HTML link to Yandex OAuth iframe URI
    """
    iframe_uri = generate_yandex_iframe_uri()
    return f'<a href="{iframe_uri}">{iframe_uri}</a>'


@app.route("/auth/yandex.html", methods=["GET"])
def auth_yandex_html():
    """
    Route for displaying the Yandex OAuth authorization page.

    Method: GET

    Returns:
    200: HTML page for Yandex OAuth
    """
    yandex_id = os.getenv('YANDEX_ID')
    api_domain = os.getenv('API_DOMAIN')
    redirect_uri = f"https://{api_domain}/auth/yandex/callback.html"
    callback_uri = f"https://{api_domain}/auth/yandex/callback"
    return auth_yandex_html_code(yandex_id, api_domain, redirect_uri, callback_uri)


@app.route("/auth/yandex/callback.html", methods=["GET"])
def auth_yandex_callback_html():
    """
    Route for handling Yandex OAuth callback and presenting a helper page.

    Method: GET

    Returns:
    200: HTML page for Yandex OAuth callback
    """

    api_domain = os.getenv('API_DOMAIN')
    callback_uri = f"https://{api_domain}/auth/yandex/callback.html"
    return auth_yandex_callback_html_code(callback_uri)
