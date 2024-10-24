# fastapi_app > error_handlers.py
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from requests.exceptions import SSLError, ConnectionError
from pydantic import ValidationError
import logging
from fastapi.exceptions import RequestValidationError  # for 422
from core.exceptions import *
from core.schemas_exceptions import *


logger = logging.getLogger(__name__)

CUSTOM_ERRORS = {"POST /auth/token/json": InsufficientAuthData,
                 "POST /auth/token/form": InsufficientAuthData,
                 "POST /auth/token/yandex/callback": InvalidOauthPostJson
                 }


def register_error_handlers(app: FastAPI):

    @app.exception_handler(400)
    async def bad_request(_request: Request, exc: Exception):
        logger.error(f"400 Bad Request: Invalid JSON sent: {str(exc)}")
        return JSONResponse(
            status_code=400,
            content={'success': False, 'message': 'Invalid JSON sent'}
        )

    @app.exception_handler(404)
    async def not_found(_request: Request, exc: Exception):
        logger.warning(f"404 Not Found: Resource not found: {str(exc)}")
        return JSONResponse(
            status_code=404,
            content={'success': False, 'message': 'Resource not found'}
        )

    @app.exception_handler(ValidationError)
    async def handle_pydantic_validation_error(request: Request, exc: ValidationError):
        logger.error(f"Validation Error: {str(exc)}")
        return JSONResponse(
            status_code=400,
            content={'success': False, 'message': str(exc)}
        )

    @app.exception_handler(405)
    async def invalid_method(request: Request, exc: Exception):
        logger.error(f"405 Method Not Allowed: Invalid method sent: {str(exc)}")
        return JSONResponse(
            status_code=405,
            content={'success': False, 'message': 'Invalid method sent'}
        )

    @app.exception_handler(500)
    async def server_error(request: Request, exc: Exception):
        logger.error(f"500 Internal Server Error: Server error: {str(exc)}")
        return JSONResponse(
            status_code=500,
            content={'success': False, 'message': 'Server error'}
        )

    @app.exception_handler(415)
    async def invalid_mediatype(request: Request, exc: Exception):
        logger.error(f"415 Unsupported Media Type: Unsupported media type: {str(exc)}")
        return JSONResponse(
            status_code=415,
            content={'success': False, 'message': 'Unsupported media type'}
        )

    @app.exception_handler(Exception)
    async def handle_general_error(request: Request, exc: Exception):
        logger.error(f"Unexpected Error: {str(exc)}")
        return JSONResponse(
            status_code=500,
            content={'success': False, 'message': f"An unexpected error occurred:  {str(exc)}"}
        )

    @app.exception_handler(SSLError)
    async def handle_ssl_error(request: Request, exc: SSLError):
        logger.error(f"503 SSL Error: SSL certificate verification failed: {str(exc)}")
        return JSONResponse(
            status_code=503,
            content={'success': False, 'message': 'SSL error occurred, certificate verification failed'}
        )

    @app.exception_handler(ConnectionError)
    async def handle_connection_error(request: Request, exc: ConnectionError):
        logger.error(f"503 Connection Error: Connection error occurred: {str(exc)}")
        return JSONResponse(
            status_code=503,
            content={'success': False, 'message': 'Connection error occurred, please try again later'}
        )

    @app.exception_handler(RequestValidationError)
    async def custom_request_validation_exception_handler(request: Request, exc: RequestValidationError):
        request_info = {
            "method": str(request.method),
            "url": str(request.url.path),
            #  "headers": dict(request.headers),
            #  "query_params": dict(request.query_params),
        }
        path = f"{request_info['method']} {request_info['url']}"
        print(path)
        if path in CUSTOM_ERRORS:
            raise CUSTOM_ERRORS[path](exc)
        # if str(request.url.path) == "/auth/token/json":
        #    raise InsufficientAuthData(exc)

        return JSONResponse(
            status_code=422,
            content={"success": False, "message": "422 Custom validation error message", "details": exc.errors(),
                     "request": request_info}
        )

    # My Error handlers

    @app.exception_handler(InsufficientAuthData)
    async def handle_insufficient_error(request: Request, exc: InsufficientAuthData):
        """ Custom error handler for 400 HTTP Error called instead FastAPI 422"""
        logger.warning(f"Processed errors: {str(exc)}")

        if isinstance(exc.errors, RequestValidationError):
            errors_list = exc.errors.errors()
        else:
            errors_list = [{"msg": str(exc)}]
        error_response = InsufficientAuthDataError(detail=errors_list)

        return JSONResponse(status_code=400, content=error_response.dict())

    @app.exception_handler(AuthenticationError)
    async def handle_auth_error(request: Request, exc: AuthenticationError):
        logger.warning(f"Authentication Error: {str(exc)}")
        error_response = ResponseAuthenticationError(message=f"Authentication Error: {str(exc)}")
        return JSONResponse(status_code=401, content=error_response.dict())

    @app.exception_handler(CustomValidationError)
    async def handle_validation_error(request: Request, exc: CustomValidationError):
        logger.error(f"Validation Error: {str(exc)}")
        return JSONResponse(
            status_code=400,  # or 401?
            content={'success': False, 'message': str(exc)}
        )

    @app.exception_handler(AdminRequiredError)
    async def handle_admin_required_error(request: Request, exc: AdminRequiredError):
        logger.warning(f"Admin Required Error: {str(exc)}")
        return JSONResponse(
            status_code=403,
            content={'success': False, 'message': str(exc)}
        )

    @app.exception_handler(UserAlreadyExistsError)
    async def handle_user_already_exists(request: Request, exc: UserAlreadyExistsError):
        logger.warning(f"User Already Exists Error: {str(exc)}")
        return JSONResponse(
            status_code=409,
            content={'success': False, 'message': str(exc)}
        )

    @app.exception_handler(DatabaseError)
    async def handle_database_error(request: Request, exc: DatabaseError):
        logger.error(f"Database Error: {str(exc)}")
        return JSONResponse(
            status_code=500,  # Internal Server Error
            content={'success': False, 'message': str(exc)}
        )

    @app.exception_handler(NoDataProvided)
    async def handle_no_data_provided(request: Request, exc: NoDataProvided):
        logger.error(f"No Data Provided Error: {str(exc)}")
        return JSONResponse(
            status_code=400,
            content={'success': False, 'message': str(exc)}
        )

    @app.exception_handler(InvalidOauthGetParams)
    async def invalid_oauth_get_params(request: Request, exc: InvalidOauthGetParams):
        logger.error(f"Invalid Get Params: {str(exc)}")
        error_response = InvalidOauthGetParamsSchema()
        return JSONResponse(status_code=400, content=error_response.dict())

    @app.exception_handler(InvalidOauthPostJson)
    async def invalid_oauth_post_json(request: Request, exc: InvalidOauthPostJson):
        """ Custom error handler for 400 HTTP Error called instead FastAPI 422"""
        logger.warning(f"Processed errors: {str(exc)}")
        if isinstance(exc.errors, RequestValidationError):
            errors_list = exc.errors.errors()
        else:
            errors_list = [{"msg": str(exc)}]
        error_response = InvalidOauthPostJsonSchema(detail=errors_list)
        return JSONResponse(status_code=400, content=error_response.dict())

    @app.exception_handler(OAuthServerError)
    async def oauth_server_error_occurred(request: Request, exc: OAuthServerError):
        logger.error(f"Ya OAuth Server Error: {str(exc)}")
        error_response = OAuthServerErrorSchema(message=f"OAuth Server Error: {str(exc)}")
        return JSONResponse(
            status_code=504,
            content=error_response.dict()
        )
