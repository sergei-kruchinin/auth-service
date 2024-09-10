import logging


def setup_logging():

    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Getting loggers for modules
    auths_models_logger = logging.getLogger('auths.models')
    auths_routes_logger = logging.getLogger('auths.routes')
    auths_yandex_oauth_logger = logging.getLogger('auths.yandex_oauth')
    auths_error_handlers_logger = logging.getLogger('auths.error_handlers')
    auths_token_service_logger = logging.getLogger('auths.token_service')

    # Setup logging levels
    auths_models_logger.setLevel(logging.CRITICAL)
    auths_routes_logger.setLevel(logging.CRITICAL)
    auths_yandex_oauth_logger.setLevel(logging.CRITICAL)
    auths_error_handlers_logger.setLevel(logging.WARNING)
    auths_token_service_logger.setLevel(logging.WARNING)
