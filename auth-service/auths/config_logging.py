import logging


def setup_logging():

    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Getting loggers for modules
    auth_models_logger = logging.getLogger('auths.models')
    auth_routes_logger = logging.getLogger('auths.routes')
    auth_error_handlers_logger = logging.getLogger('auths.error_handlers')

    # Setup logging levels
    auth_models_logger.setLevel(logging.DEBUG)
    auth_routes_logger.setLevel(logging.INFO)
    auth_error_handlers_logger.setLevel(logging.WARNING)
