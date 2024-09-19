# config > logging_config.conf

import logging


def setup_logging():

    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Getting loggers for modules
    core_models_logger = logging.getLogger('core.models')
    flask_app_routes_auth_logger = logging.getLogger('flask_app.routes.auth')
    flask_app_routes_front_emu_logger = logging.getLogger('flask_app.routes.front_emu')
    flask_app_routes_dependencies_logger = logging.getLogger('flask_app.routes.dependencies')
    core_yandex_oauth_logger = logging.getLogger('core.yandex_oauth')
    flask_app_error_handlers_logger = logging.getLogger('flask_app.error_handlers')
    core_password_hash_logger = logging.getLogger('core.password_hash')
    core_token_service_logger = logging.getLogger('core.token_service')

    # Setup logging levels
    core_models_logger.setLevel(logging.INFO)
    flask_app_routes_auth_logger.setLevel(logging.INFO)
    flask_app_routes_front_emu_logger.setLevel(logging.INFO)
    flask_app_routes_dependencies_logger.setLevel(logging.INFO)
    core_yandex_oauth_logger.setLevel(logging.INFO)
    flask_app_error_handlers_logger.setLevel(logging.INFO)
    core_password_hash_logger.setLevel(logging.INFO)
    core_token_service_logger.setLevel(logging.INFO)
