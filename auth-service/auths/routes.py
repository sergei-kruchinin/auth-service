import base64
from functools import wraps

import requests

from flask import request

from . import app
from .models import *
from .yandex_html import *
from .schemas import AuthRequest, UserCreateInputSchema, YandexUserInfo
from pydantic import ValidationError
from .exceptions import *
from .token_service import TokenService
import os


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
            verification = TokenService.verify_token(token)
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
    - token (GET, query parameter): The OAuth token
    - code (GET, query parameter): The authorization code from Yandex
    Returns:
    200: JSON containing authentication token
    503: If there's an OAuth or user data retrieval error
    """

    def get_token_from_code(auth_code):
        yandex_url = 'https://oauth.yandex.ru/token'
        client_id = os.getenv('YANDEX_ID')
        client_secret = os.getenv('YANDEX_SECRET')

        client_id_sec = f'{client_id}:{client_secret}'
        client_id_sec_base64_encoded = base64.b64encode(client_id_sec.encode()).decode()
        headers = {'Authorization': f'Basic {client_id_sec_base64_encoded}'}
        params = {'grant_type': 'authorization_code', 'code': auth_code}

        response = requests.post(yandex_url, headers=headers, data=params)
        response.raise_for_status()
        return response.json().get('access_token')

    def get_user_info(access_token):
        headers = {'Authorization': f'OAuth {access_token}'}
        yandex_url = 'https://login.yandex.ru/info'

        response = requests.get(yandex_url, headers=headers)
        response.raise_for_status()
        return response.json()

    access_token = None
    auth_code = None
    if request.method == 'POST':
        # In POST requests, we always receive the token.
        access_token = request.json.get('token')
    else:  # GET
        access_token = request.args.get('token')
        auth_code = request.args.get('code')

        # Token and code are never returned at the same time in GET requests.
        # We can use GET to get either the token or the code.
        # If we receive a code, we have to exchange it for a token.

        if access_token is None and auth_code is not None:
            try:
                access_token = get_token_from_code(auth_code)
            except requests.exceptions.RequestException as e:
                raise OAuthServerError(f'Yandex OAuth error: {str(e)}')

    if access_token is None:
        raise OAuthServerError('Token or authorization code is missing')

    try:
        raw_user_info = get_user_info(access_token)
        user_info = YandexUserInfo(**raw_user_info)
    except requests.exceptions.RequestException as e:
        raise OAuthUserDataRetrievalError(f'Unable to retrieve user data: {str(e)}') from e
    except ValidationError as e:
        raise CustomValidationError(f'Invalid user data received from Yandex: {str(e)}') from e

    # add to our database (or update)
    try:
        user = Users.create_or_update_oauth_user(
            first_name=user_info.first_name,
            last_name=user_info.last_name,
            is_admin=False,
            source='yandex',
            oa_id=user_info.id)
        authentication = Users.authenticate_oauth(user.login)
    except DatabaseError as e:
        raise DatabaseError(f"There was an error while syncing the user from yandex: {str(e)}") from e

    return authentication, 200


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
    # Till @token_required(notify_on_failure=True) be implemented,
    # by now it not be executed. @token_required on not authenticated raises exception 401
    # if not verification:  # if verification returned None or failed
    #     return {'success': False, 'message': 'Invalid or expired token'}, 401

    try:
        TokenService.add_to_blacklist(token)
        message = 'Token has been invalidated (added to blacklist).'
        status = True
    except DatabaseError as e:
        raise DatabaseError('Error checking if token is blacklisted') from e

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
    409: If user already exists
    500: If there's an error creating the user
    """
    if not verification.get("is_admin"):
        raise AdminRequiredError("Access Denied")

    json_data = request.get_json()
    if not json_data:
        raise CustomValidationError("No input data provided")
    try:
        user_data = UserCreateInputSchema(**json_data)
    except ValidationError as e:
        raise CustomValidationError(str(e)) from e

    try:
        Users.create_with_check(user_data.dict())

    except UserAlreadyExistsError as e:
        raise UserAlreadyExistsError(e) from e
    except DatabaseError as e:
        raise DatabaseError(f"There was an error while creating a user: {str(e)}") from e

    return {'success': True}, 201


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
        raise DatabaseError(f"There was an error while retrieving the users list {str(e)}") from e

    return users_list_json


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


# Some helper routes


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
