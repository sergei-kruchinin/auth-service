# flask_app > routes > front_emu.py

from core.models import *
# from .yandex_html import *
from .dependencies import get_yandex_uri
from flask import render_template, Blueprint

import os
import logging

logger = logging.getLogger(__name__)


def register_routes(bp: Blueprint):

    # ### 4. Root Route Method: ###

    @bp.route("/", methods=["GET"])
    def site_root():
        """
        Root route for the application (Temporary/Dummy)

        Method: GET

        Returns:
        200: HTML page with "hello world".
        """
        logger.info("Root route called")
        return '<html><body>Hello world</body></html>'

    # ### 5. Frontend Imitation Methods for testing Yandex OAuth 2.0 ###

    @bp.route("/auth/yandex/by_code.html", methods=["GET"])
    def auth_yandex_by_code_html():
        """
        Route for displaying the link to Yandex OAuth authorization page.

        Method: GET

        Returns:
        200: HTML link to Yandex OAuth iframe URI
        """
        logger.info("Yandex OAuth by code HTML called")
        iframe_uri = get_yandex_uri()
        return f'<a href="{iframe_uri}">{iframe_uri}</a>'

    @bp.route("/auth/yandex.html", methods=["GET"])
    def auth_yandex_html():
        """
        Route for displaying the Yandex OAuth authorization page.

        Method: GET

        Returns:
        200: HTML page for Yandex OAuth
        """
        logger.info("Yandex OAuth HTML called")
        yandex_id = os.getenv('YANDEX_ID')
        api_domain = os.getenv('API_DOMAIN')
        redirect_uri = f"https://{api_domain}/auth/yandex/callback.html"
        callback_uri = f"https://{api_domain}/auth/yandex/callback"
        # return auth_yandex_html_code(yandex_id, api_domain, redirect_uri, callback_uri)
        return render_template('auth_yandex.html', yandex_id=yandex_id, api_domain=api_domain,
                               redirect_uri=redirect_uri, callback_uri=callback_uri)

    @bp.route("/auth/yandex/callback.html", methods=["GET"])
    def auth_yandex_callback_html():
        """
        Route for handling Yandex OAuth callback and presenting a helper page.

        Method: GET

        Returns:
        200: HTML page for Yandex OAuth callback
        """
        logger.info("Yandex OAuth callback HTML called")
        api_domain = os.getenv('API_DOMAIN')
        callback_uri = f"https://{api_domain}/auth/yandex/callback.html"
        # return auth_yandex_callback_html_code(callback_uri)
        return render_template('yandex_callback.html', callback_uri=callback_uri)
