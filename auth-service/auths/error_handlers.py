from .exceptions import *
from requests.exceptions import SSLError, ConnectionError
from pydantic import ValidationError


def register_error_handlers(app):
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
        return {'success': False, 'message': str(e)}, 400

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
        return {'success': False, 'message': str(e)}, 401

    @app.errorhandler(CustomValidationError)
    def handle_validation_error(e):
        return {'success': False, 'message': str(e)}, 400  # or 401?

    @app.errorhandler(AdminRequiredError)
    def handle_admin_required_error(e):
        return {'success': False, 'message': str(e)}, 403

    @app.errorhandler(UserAlreadyExistsError)
    def handle_user_already_exists(e):
        return {'success': False, 'message': str(e)}, 409

    @app.errorhandler(DatabaseError)
    def handle_database_error(e):
        return {'success': False, 'message': str(e)}, 500  # Internal Server Error

    @app.errorhandler(NoDataProvided)
    def handle_no_data_provided(e):
        return {'success': False, 'message': str(e)}, 400

    @app.errorhandler(OAuthServerError)
    def oauth_server_error_occurred(e):
        return {'success': False, 'error': str(e)}, 503

    return app
