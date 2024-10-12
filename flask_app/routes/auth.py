# flask_app > routes > auth.py
import requests
from flask import Blueprint, make_response, Response
from pydantic import ValidationError
import logging
from sqlalchemy.orm import Session

from core.schemas import AuthRequest, AuthTokens, ManualUserCreateSchema, TokenVerification
from core.models.user import *
from .dependencies import *
from core.yandex_oauth import YandexOAuthService
from core.exceptions import *
from core.token_service import TokenType


logger = logging.getLogger(__name__)


# ### 1. User Authentication Methods: ###

def create_auth_response(authentication: AuthTokens) -> Response:
    """
    Create JSON response with the access token and set the refresh token in http-only cookie.

    Args:
        authentication (AuthTokens): The authentication response containing tokens.

    Returns:
        Response: Flask response object with access token in JSON and refresh token in cookie.
    """
    logger.info("Creating auth response")

    access_token = authentication.tokens[TokenType.ACCESS.value]
    refresh_token = authentication.tokens[TokenType.REFRESH.value]

    # Convert access token from TokenData to TokenDataResponse
    access_token_response = access_token.to_response().dict()

    # Create response object with access token
    response = make_response(access_token_response, 200)

    # Set the refresh token in http-only cookie
    response.set_cookie(
        'refresh_token',
        refresh_token.value,
        httponly=True,
        secure=True,    # Use True in production to enforce HTTPS
        samesite='Lax'  # Can be adjusted depending on your needs (Strict/Lax/None)
    )
    logger.info("Auth response created")
    return response


def register_routes(bp: Blueprint):
    @bp.route("/token/json", methods=["POST"])
    @with_db
    def auth(db: Session) -> Response:
        """
        Route for authenticating a user.

        Request body:
        {
            "username": "<username>",
            "password": "<password>"
        }

        Returns:
        200: {'token': '<token>', 'expires_in': <expires_in>}
        400: If no data is provided
        401: For invalid username/password
        """
        logger.info("Auth route called")
        try:
            json_data = request.get_json()
            if not json_data:
                raise NoDataProvided('No input data provided')
            device_fingerprint = get_device_fingerprint()
            json_data["device_fingerprint"] = device_fingerprint
            auth_request = AuthRequestFingerPrinted(**json_data)
            authentication = User.authenticate(db, auth_request)

        except ValidationError as e:
            raise InsufficientAuthData('username or password not specified') from e
        except AuthenticationError as e:
            raise AuthenticationError('Invalid username or password') from e

        logger.info("User authenticated successfully")

        return create_auth_response(authentication)

    @bp.route("/auth/yandex/callback", methods=["POST", "GET"])
    @with_db
    def auth_yandex_callback(db: Session) -> Response:
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
        logger.info("Received Yandex OAuth callback request")
        device_fingerprint = get_device_fingerprint()
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
                    access_token = YandexOAuthService.get_token_from_code(auth_code)
                except requests.exceptions.RequestException as e:
                    logger.error(f'Yandex OAuth error: {str(e)}')
                    raise OAuthTokenRetrievalError(f'Yandex OAuth error')

        if access_token is None:
            logger.error('access_token is None: Token or authorization code is missing')
            raise OAuthServerError('Token or authorization code is missing')

        try:
            yandex_user_info = YandexOAuthService.get_user_info(access_token)
            logger.info("Successfully retrieved user info from Yandex")
        except requests.exceptions.RequestException as e:
            logger.error(f'Unable to retrieve user data: {str(e)}')
            raise OAuthUserDataRetrievalError(f'Unable to retrieve user data: {str(e)} ?') from e
        except ValidationError as e:
            logger.error(f"Invalid user data received from Yandex: {str(e)}")
            raise CustomValidationError(f'Invalid user data received from Yandex: {str(e)} ? ') from e

        # add to our database (or update)
        try:
            oauth_user_data = YandexOAuthService.yandex_user_info_to_oauth(yandex_user_info)
            user = User.create_or_update_oauth_user(db, oauth_user_data)
            authentication = user.authenticate_oauth(device_fingerprint)
        except DatabaseError as e:
            logger.error(f"There was an error while syncing the user from yandex: {str(e)}")
            raise DatabaseError(f"There was an error while syncing the user from yandex") from e

        logger.info("Yandex user authenticated successfully")

        return create_auth_response(authentication)

    @bp.route("/auth/yandex/by_code", methods=["GET"])
    def auth_yandex_by_code() -> Response:
        """
        Route for generating Yandex OAuth authorization URI.

        Method: GET

        Returns:
        200: JSON containing the iframe URI
        """
        logger.info("Yandex OAuth by code called")
        iframe_uri = get_yandex_uri()
        response = make_response({'iframe_uri': iframe_uri}, 200)
        return response

    # ### 2. Token Verification and Invalidation Methods ###

    @bp.route("/verify", methods=["POST"])
    @token_required
    def verify(verification: TokenVerification) -> Response:
        """
        Route for verifying an authentication token.

        Method: POST

        Headers:
        - Authorization: Bearer <token>

        Returns:
        200: JSON containing verification status
        401: For invalid or expired tokens
        """
        logger.info("Verify route called")
        response = make_response(verification.dict(), 200)
        return response

    @bp.route("/logout", methods=["POST"])
    @token_required
    def logout(verification: TokenVerification) -> Response:
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
        logger.info("Logout route called")

        try:
            token = verification.access_token
            TokenService.add_to_blacklist(token)
            message = 'Token has been invalidated (added to blacklist).'
            status = True
        except DatabaseError as e:
            raise DatabaseError('Error checking if token is blacklisted') from e

        response = make_response({'success': status, 'message': message}, 200)
        return response

    # TODO make a logout from all devices
    # TODO make a list of username devices, needed it for logout
    # TODO is_system and source and source_id usage in routes and methods(?)

    # ### 3. User Management Methods: ###

    @bp.route("/users", methods=["POST"])
    @token_required
    @with_db
    def users_create(verification: TokenVerification, db: Session) -> Response:
        """
        Route for creating a new user (admin only).

        Method: POST

        Headers:
        - Authorization: Bearer <admin_token>

        Request body (JSON):
        {
            "username": "<username>",
            "first_name": "<first_name>",
            "last_name": "<last_name>",
            "password": "<password>",
            "is_admin": <true/false>
            "source": "<manual>",
            "oa_id" : "<null>"
        }

        Returns:
        201: {'success': True}
        400: If input data is invalid
        403: If user is not an admin
        409: If user already exists
        500: If there's an error creating the user
        """
        logger.info("Create user route called")

        if not verification.is_admin:
            logger.warning("is_admin if False")
            raise AdminRequiredError("Access Denied")

        json_data = request.get_json()
        if not json_data:
            logger.error("No input data provided")
            raise CustomValidationError("No input data provided")
        try:
            user_data = ManualUserCreateSchema(**json_data) # not correct schema
        except ValidationError as e:
            logger.warning(f"Not Correct ManualUserCreateSchema for manual user: {str(e)}")
            raise InsufficientAuthData(f"Invalid username format") from e

        try:
            User.create_with_check(db, user_data)
        except UserAlreadyExistsError as e:
            logger.warning(f"User with username already exists: {str(e)}")
            raise
        except DatabaseError as e:
            logger.error(f"There was an error while creating a user: {str(e)}")
            raise DatabaseError(f"There was an error while creating a user") from e

        logger.info("User created successfully")
        response = make_response({'success': True}, 201)
        return response

    @bp.route("/users", methods=["GET"])
    @token_required
    @with_db
    def users_list(verification: TokenVerification, db: Session) -> Response:
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
        logger.info("Fetching list of users")
        if not verification.is_admin:
            logger.warning("is_admin is False")
            raise AdminRequiredError('Access Denied')
        try:
            users_list_json = User.list(db)
            logger.info("Users list retrieved successfully")

            response = make_response(users_list_json, 200)
            return response

        except DatabaseError as e:
            logger.error(f"here was an error while retrieving the users list. DatabaseError: {e}")
            raise DatabaseError(f"There was an error while retrieving the users list.") from e
