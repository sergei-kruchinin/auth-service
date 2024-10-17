# fastapi_app > routes > auth.py

from fastapi import APIRouter, Depends, Request, Response, Header
from typing import Annotated, Optional
from sqlalchemy.orm import Session
import logging
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm

from core.schemas import *
from core.schemas_exceptions import *
from core.models.user import User
from fastapi_app.routes.dependencies import (get_db_session, token_required, get_yandex_uri)
from core.yandex_oauth_async import YandexOAuthService
from core.exceptions import *
from core.token_service import TokenType, TokenService

logger = logging.getLogger(__name__)


def create_auth_response(authentication: AuthTokens) -> Response:
    """
    Create JSON response with the access token and set the refresh token in HTTP-only cookie.

    Args:
        authentication (AuthTokens): The authentication response containing tokens.

    Returns:
        Response: FastAPI response object with access token in JSON and refresh token in cookie.
    """
    logger.info("Creating auth response")

    access_token = authentication.tokens[TokenType.ACCESS.value]
    refresh_token = authentication.tokens[TokenType.REFRESH.value]

    # Convert access token from TokenData to TokenDataResponse
    response_data = access_token.to_response().dict()
    response = JSONResponse(content=response_data, status_code=200)
    # Set the refresh token in HTTP-only cookie
    response.set_cookie(
        'refresh_token',
        refresh_token.value,
        httponly=True,
        secure=True,  # Use True in production to enforce HTTPS
        samesite='lax'  # Can be adjusted depending on your needs (Strict/Lax/None)
    )
    logger.info("Auth response created")

    return response


async def authenticate_with_yandex_token(yandex_access_token: YandexAccessToken,
                                         db, device_fingerprint: RawFingerPrint) -> Response:
    try:
        yandex_user_info = await YandexOAuthService.get_user_info(yandex_access_token.token)
        logger.info("Successfully retrieved user info from Yandex")
    except OAuthUserDataRetrievalError as e:
        logger.error(f'Unable to retrieve user data: {str(e)}')
        raise

    oauth_user_data = YandexOAuthService.yandex_user_info_to_oauth(yandex_user_info)
    user = User.create_or_update_oauth_user(db, oauth_user_data)
    authentication = user.authenticate_oauth(device_fingerprint.to_fingerprint())  # Maybe to be better use schema

    logger.info("Yandex user authenticated successfully")
    return create_auth_response(authentication)


def register_routes(router: APIRouter):
    auth_router = APIRouter()

    @auth_router.post("/token/json", response_model=TokenDataResponse, responses={
        401: {"model": ResponseAuthenticationError},
        400: {"model": InsufficientAuthDataError}
        }
    )
    async def token_json(
            auth_request: AuthRequest,
            device_fingerprint: Annotated[RawFingerPrint, Header()],
            db: Session = Depends(get_db_session)
    ) -> Response:
        """
        Route for authenticating a user.
        """
        logger.info("Auth json route called")

        try:
            auth_request_fingerprinted = auth_request.to_fingerprinted(device_fingerprint)
            authentication = User.authenticate(db, auth_request_fingerprinted)
        # except ValidationError as e:
        #     raise InsufficientAuthData('username or password not specified') from e
        except AuthenticationError as e:
            raise AuthenticationError('Invalid username or password') from e

        logger.info("User authenticated successfully")

        return create_auth_response(authentication)

    @auth_router.post("/token/form", response_model=TokenDataResponse, responses={
            401: {"model": ResponseAuthenticationError},
            400: {"model": InsufficientAuthDataError}
        })
    async def token_form(
                device_fingerprint: Annotated[RawFingerPrint, Header()],
                form_data: OAuth2PasswordRequestForm = Depends(),
                db: Session = Depends(get_db_session)
    ) -> Response:
        """
        Route for authenticating a user by post form (for swagger).
        """

        logger.info("Auth form route called")
        try:
            username = form_data.username
            password = form_data.password
            auth_request = AuthRequest(username=username, password=password)
            auth_request_fingerprinted = auth_request.to_fingerprinted(device_fingerprint)
            authentication = User.authenticate(db, auth_request_fingerprinted)
        # except ValidationError as e:
        #     raise InsufficientAuthData('username or password not specified') from e
        except AuthenticationError as e:
            raise AuthenticationError('Invalid username or password') from e
        logger.info("User authenticated successfully")

        return create_auth_response(authentication)

    @auth_router.post("/token/yandex/callback", response_model=TokenDataResponse, responses={
        400: {"model": InvalidOauthPostJsonSchema},
        504: {"model": OAuthServerErrorSchema}
    })
    async def auth_yandex_callback_post(
            device_fingerprint: Annotated[RawFingerPrint, Header()],
            yandex_access_token: YandexAccessToken,
            db: Session = Depends(get_db_session)
    ) -> Response:
        """
        Route for handling Yandex OAuth callback (POST).
        """
        logger.info("Received Yandex OAuth POST callback request")
        return await authenticate_with_yandex_token(yandex_access_token, db, device_fingerprint)

    @auth_router.get("/token/yandex/callback", response_model=TokenDataResponse, responses={
        400: {"model": InvalidOauthGetParamsSchema},
        503: {"model": OAuthServerErrorSchema},
        504: {"model": OAuthServerErrorSchema}
    })
    async def auth_yandex_callback_get(
            device_fingerprint: Annotated[RawFingerPrint, Header()],
            query_params: YandexCallbackQueryParams = Depends(),
            db: Session = Depends(get_db_session)
    ) -> Response:
        """
        Route for handling Yandex OAuth callback (GET).
        """
        logger.info("Received Yandex OAuth GET callback request")

        if query_params.token is None:
            try:
                query_params.token = await YandexOAuthService.get_token_from_code(query_params.code)
            except OAuthTokenRetrievalError as e:
                logger.error(f'Yandex OAuth error: {str(e)}')
                raise

        yandex_access_token = query_params.to_yandex_access_token()

        return await authenticate_with_yandex_token(yandex_access_token, db, device_fingerprint)

    @auth_router.get("/yandex/by_code", response_model=IframeUrlResponse)
    async def auth_yandex_by_code() -> Response:
        """
        Route for generating Yandex OAuth authorization URI.
        """

        logger.info("Yandex OAuth by code called")
        response_data = IframeUrlResponse(iframe_uri=get_yandex_uri())
        response = JSONResponse(response_data, status_code=200)
        return response

    @auth_router.post("/verify", response_model=TokenVerification, responses={
                    401: {"model": TokenInvalidErrorSchema}
                    })
    async def verify(
            verification: TokenVerification = Depends(token_required)
    ) -> Response:
        """
        Route for verifying an authentication token.

        """
        logger.info(f"Verify route called: {verification}")
        response_data = verification.dict()
        logger.info(f"Converting to dict: {response_data}")

        response = JSONResponse(response_data, status_code=200)

        logger.info("Verify response created")

        return response

    @auth_router.post("/logout", response_model=SimpleResponseStatus)
    async def logout(
            verification: TokenVerification = Depends(token_required)
    ) -> Response:
        """
        Route for logging out a user and invalidating the token.

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
        response_data = SimpleResponseStatus(success=status, message=message).dict()
        response = JSONResponse(content=response_data, status_code=200)
        return response

    @auth_router.post("/_users", response_model=SimpleResponseStatus)
    async def users_create(
            user_to_create: ManualUserCreateSchema,
            verification: TokenVerification = Depends(token_required),
            db: Session = Depends(get_db_session)
    ) -> Response:
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
            logger.warning("is_admin is False")
            raise AdminRequiredError("Access Denied")

        try:
            user = User.create_with_check(db, user_to_create)
        except UserAlreadyExistsError as e:
            logger.warning(f"User with username already exists: {str(e)}")
            raise
        except DatabaseError as e:
            logger.error(f"There was an error while creating a user {user_to_create.username}: {str(e)}")
            raise DatabaseError(f"There was an error while creating a user ") from e

        response_data = SimpleResponseStatus(success=True, message=f'User {user.username} created').dict()
        logger.info("User created successfully")
        return JSONResponse(
            status_code=201,
            content=response_data
        )

    @auth_router.get("/_users", response_model=UsersResponseSchema)
    async def users_list(
            verification: TokenVerification = Depends(token_required),
            db: Session = Depends(get_db_session)
    ) -> UsersResponseSchema:
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
            users_list_data = User.list(db)  # Retrieve user data from the database
            users_list_json = users_list_data.get('users', [])
            users_list = [UserResponseSchema(**user) for user in
                          users_list_json]  # Convert to list of UserResponseSchema objects
            logger.info("Users list retrieved successfully")
            return UsersResponseSchema(users=users_list)
        except Exception as e:
            logger.error(f"There was an error while retrieving the users list. Error: {e}")
            raise DatabaseError(f"There was an error while retrieving the users list.") from e

    router.include_router(auth_router, prefix="/auth")
    print(f"Auth routes registered: {[route.path for route in router.routes if hasattr(route, 'path')]}")
