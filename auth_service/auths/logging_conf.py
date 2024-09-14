# auths > logging.conf

import logging


def setup_logging():

    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Getting loggers for modules
    auths_models_logger = logging.getLogger('auths.models')
    auths_routes_auth_logger = logging.getLogger('auths.routes.auth')
    auths_routes_front_emu_logger = logging.getLogger('auths.routes.front_emu')
    auths_routes_dependencies_logger = logging.getLogger('auths.routes.dependencies')
    auths_yandex_oauth_logger = logging.getLogger('auths.yandex_oauth')
    auths_error_handlers_logger = logging.getLogger('auths.error_handlers')
    auths_token_service_logger = logging.getLogger('auths.token_service')
    password_hash_logger = logging.getLogger('auths.password_hash')

    # Setup logging levels
    auths_models_logger.setLevel(logging.INFO)
    auths_routes_auth_logger.setLevel(logging.INFO)
    auths_routes_front_emu_logger.setLevel(logging.INFO)
    auths_routes_dependencies_logger.setLevel(logging.INFO)
    auths_yandex_oauth_logger.setLevel(logging.INFO)
    auths_error_handlers_logger.setLevel(logging.INFO)
    auths_token_service_logger.setLevel(logging.INFO)
    password_hash_logger.setLevel(logging.INFO)
