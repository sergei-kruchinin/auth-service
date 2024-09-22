# fastapi_app > routes > auth.py

from fastapi import APIRouter, Depends, Request, HTTPException, status, Response
from sqlalchemy.orm import Session
from typing import List
import logging
import requests  # to refactor
from pydantic import ValidationError
from fastapi.responses import JSONResponse


from core.schemas import AuthRequest, AuthTokens, ManualUserCreateSchema, TokenVerification, UserResponseSchema
from core.models.user import User
from fastapi_app.routes.dependencies import get_db_session, token_required, get_device_fingerprint, get_yandex_uri
from core.yandex_oauth import YandexOAuthService
from core.exceptions import *
from core.token_service import TokenType, TokenService

logger = logging.getLogger(__name__)


def create_auth_response(authentication: AuthTokens, response: Response):
    """Create JSON response with the access token and set the refresh token in HTTP-only cookie."""
    logger.info("Creating auth response")

    access_token = authentication.tokens[TokenType.ACCESS.value]
    refresh_token = authentication.tokens[TokenType.REFRESH.value]

    # Convert access token from TokenData to TokenDataResponse
    access_token_response = access_token.to_response().dict()

    # Set the refresh token in HTTP-only cookie
    response.set_cookie(
        'refresh_token',
        refresh_token.value,
        httponly=True,
        secure=True,  # Use True in production to enforce HTTPS
        samesite='lax'  # Can be adjusted depending on your needs (Strict/Lax/None)
    )
    logger.info("Auth response created")
    return access_token_response


def register_routes(router: APIRouter):
    auth_router = APIRouter()

    @auth_router.post("/auth")
    async def auth(
            request: Request,
            db: Session = Depends(get_db_session)
    ) -> dict:
        """Route for authenticating a user."""
        logger.info("Auth route called")
        try:
            json_data = await request.json()
            if not json_data:
                raise NoDataProvided('No input data provided')
            device_fingerprint = get_device_fingerprint(request)
            json_data["device_fingerprint"] = device_fingerprint
            auth_request = AuthRequest(**json_data)
            authentication = User.authenticate(db, auth_request)
        except ValidationError as e:
            raise InsufficientData('login or password not specified') from e
        except AuthenticationError as e:
            raise AuthenticationError('Invalid login or password') from e

        logger.info("User authenticated successfully")

        response = Response(status_code=200)
        return create_auth_response(authentication, response)

    @auth_router.post("/auth/yandex/callback")
    @auth_router.get("/auth/yandex/callback")
    async def auth_yandex_callback(
            request: Request,
            db: Session = Depends(get_db_session)
    ) -> dict:
        """Route for handling Yandex OAuth callback."""
        logger.info("Received Yandex OAuth callback request")
        device_fingerprint = get_device_fingerprint(request)
        if request.method == 'POST':
            json_data = await request.json()
            access_token = json_data.get('token')
        else:  # GET
            access_token = request.query_params.get('token')
            auth_code = request.query_params.get('code')

            if access_token is None and auth_code is not None:
                try:
                    access_token = YandexOAuthService.get_token_from_code(auth_code)
                except requests.exceptions.RequestException as e:  # to refactor
                    logger.error(f'Yandex OAuth error: {str(e)}')
                    raise OAuthTokenRetrievalError(f'Yandex OAuth error')

        if access_token is None:
            logger.error('access_token is None: Token or authorization code is missing')
            raise OAuthServerError('Token or authorization code is missing')

        try:
            yandex_user_info = YandexOAuthService.get_user_info(access_token)
            logger.info("Successfully retrieved user info from Yandex")
        except requests.exceptions.RequestException as e:  # to refactor
            logger.error(f'Unable to retrieve user data: {str(e)}')
            raise OAuthUserDataRetrievalError(f'Unable to retrieve user data: {str(e)}') from e
        except ValidationError as e:
            logger.error(f"Invalid user data received from Yandex: {str(e)}")
            raise CustomValidationError(f'Invalid user data received from Yandex: {str(e)}') from e

        try:
            oauth_user_data = YandexOAuthService.yandex_user_info_to_oauth(yandex_user_info)
            user = User.create_or_update_oauth_user(db, oauth_user_data)
            authentication = user.authenticate_oauth(device_fingerprint)
        except DatabaseError as e:
            logger.error(f"There was an error while syncing the user from yandex: {str(e)}")
            raise DatabaseError(f"There was an error while syncing the user from yandex") from e

        logger.info("Yandex user authenticated successfully")

        response = Response(status_code=200)
        return create_auth_response(authentication, response)

    @auth_router.get("/auth/yandex/by_code")
    async def auth_yandex_by_code() -> dict:
        """Route for generating Yandex OAuth authorization URI."""
        logger.info("Yandex OAuth by code called")
        iframe_uri = get_yandex_uri()
        return {'iframe_uri': iframe_uri}

    @auth_router.post("/verify")
    async def verify(
            verification: TokenVerification = Depends(token_required)
    ) -> dict:
        """Route for verifying an authentication token."""
        logger.info("Verify route called")
        return verification.dict()

    @auth_router.post("/logout")
    async def logout(
            verification: TokenVerification = Depends(token_required)
    ) -> dict:
        """Route for logging out a user and invalidating the token."""
        logger.info("Logout route called")
        try:
            token = verification.access_token
            TokenService.add_to_blacklist(token)
            message = 'Token has been invalidated (added to blacklist).'
            status = True
        except DatabaseError as e:
            raise DatabaseError('Error checking if token is blacklisted') from e

        return {'success': status, 'message': message}

    @auth_router.post("/users")
    async def users_create(
            json_data: ManualUserCreateSchema,
            verification: TokenVerification = Depends(token_required),
            db: Session = Depends(get_db_session)
    ) -> Response:
        """Route for creating a new user (admin only)."""
        logger.info("Create user route called")

        if not verification.is_admin:
            logger.warning("is_admin is False")
            raise AdminRequiredError("Access Denied")

        try:
            User.create_with_check(db, json_data)
        except UserAlreadyExistsError as e:
            logger.warning(f"User with login already exists: {str(e)}")
            raise
        except DatabaseError as e:
            logger.error(f"There was an error while creating a user: {str(e)}")
            raise DatabaseError(f"There was an error while creating a user") from e

        logger.info("User created successfully")
        return JSONResponse(
            status_code=201,
            content={'success': True, 'message': 'User created'}
        )

    @auth_router.get("/users", response_model=List[UserResponseSchema])
    async def users_list(
        verification: TokenVerification = Depends(token_required),
        db: Session = Depends(get_db_session)
    ) -> List[UserResponseSchema]:
        """Route for retrieving the list of users (admin only)."""
        logger.info("Fetching list of users")
        if not verification.is_admin:
            logger.warning("is_admin is False")
            raise AdminRequiredError('Access Denied')
        try:
            users_list_data = User.list(db)
            users_list_json = users_list_data.get('users', [])
            users_list = [UserResponseSchema(**user) for user in
                          users_list_json]  # Convert to list of objects UserResponseSchema
            logger.info("Users list retrieved successfully")
            return users_list
        except DatabaseError as e:
            logger.error(f"There was an error while retrieving the users list. DatabaseError: {e}")
            raise DatabaseError(f"There was an error while retrieving the users list.") from e

    router.include_router(auth_router, prefix="")
    print(f"Auth routes registered: {[route.path for route in router.routes if hasattr(route, 'path')]}")
