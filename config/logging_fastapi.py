# config > logging_fastapi.conf

import logging


def setup_logging():

    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Getting loggers for modules
    core_models_user_logger = logging.getLogger('core.models.user')
    core_models_user_session_logger = logging.getLogger('core.models.user_session')
    fastapi_app_routes_auth_logger = logging.getLogger('fastapi_app.routes.auth')
    fastapi_app_routes_front_emu_logger = logging.getLogger('fastapi_app.routes.front_emu')
    fastapi_app_routes_dependencies_logger = logging.getLogger('fastapi_app.routes.dependencies')
    core_yandex_oauth_logger = logging.getLogger('core.yandex_oauth')
    fastapi_app_error_handlers_logger = logging.getLogger('fastapi_app.error_handlers')
    core_password_hash_logger = logging.getLogger('core.password_hash')
    core_token_service_logger = logging.getLogger('core.token_service')

    # Setup logging levels
    core_models_user_logger.setLevel(logging.INFO)
    core_models_user_session_logger.setLevel(logging.INFO)
    fastapi_app_routes_auth_logger.setLevel(logging.INFO)
    fastapi_app_routes_front_emu_logger.setLevel(logging.INFO)
    fastapi_app_routes_dependencies_logger.setLevel(logging.INFO)
    core_yandex_oauth_logger.setLevel(logging.INFO)
    fastapi_app_error_handlers_logger.setLevel(logging.INFO)
    core_password_hash_logger.setLevel(logging.INFO)
    core_token_service_logger.setLevel(logging.INFO)