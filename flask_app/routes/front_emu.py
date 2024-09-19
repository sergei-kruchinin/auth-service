# flask_app > routes > front_emu.py

from core.models import *
from .dependencies import get_yandex_uri
from flask import render_template, Blueprint
import requests
import markdown
import os
import logging

logger = logging.getLogger(__name__)


def register_routes(bp: Blueprint):

    # ### 4. Root Route Method: ###

    @bp.route("/", methods=["GET"])
    def display_readme():
        """
        Default route that fetches and displays the README.md file as HTML.

        This function performs the following steps:
        1. Attempts to read the local README.md file from the project root.
        2. If the local file is not found, it fetches the raw content of the README.md file from the given URL.
        3. Converts the Markdown content to HTML.
        4. Renders an HTML template to display the converted content.

        Returns:
            Response: The rendered HTML containing the contents of the README.md file.

        Raises:
            HTTPException: If there is an error fetching the README.md file,
                           returns an appropriate HTTP error response.
        """

        logger.info("Root route called")
        md_content = ""
        readme_local_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "README.md")

        # Attempt to read the local README.md file
        try:
            logger.info(f"Trying to read the local file at {readme_local_path}")
            with open(readme_local_path, "r", encoding="utf-8") as file:
                md_content = file.read()
                logger.info("Successfully read the local README.md file")
        except FileNotFoundError:
            logger.warning(f"Local README.md file not found at {readme_local_path}, trying to fetch from the URL")
            url = "https://raw.githubusercontent.com/sergei-kruchinin/flask-auth-service/main/README.md"
            response = requests.get(url)

            if response.status_code != 200:
                logger.warning(
                    f"Failed to fetch the README.md file from URL. Response status code: {response.status_code}")
                return "Failed to fetch the README.md file", response.status_code

            md_content = response.text

        logger.info("Converting Markdown to HTML")
        html_content = markdown.markdown(md_content)

        logger.info("Rendering template")
        try:
            return render_template("readme_md.html", html_content=html_content)
        except Exception as e:
            logger.error(f"Unexpected Error rendering template: {str(e)}")
            return str(e), 500

    @bp.route("/LICENSE", methods=["GET"])
    def display_license():
        """
        Route that fetches and displays the LICENSE file as plain text.

        This function performs the following steps:
        1. Attempts to read the local LICENSE file from the project root.
        2. Renders a plain text template to display the content.

        Returns:
            Response: The rendered plain text containing the contents of the LICENSE file.

        Raises:
            HTTPException: If there is an error fetching the LICENSE file,
                           returns an appropriate HTTP error response.
        """

        logger.info("License route called")
        license_content = ""
        license_local_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "LICENSE")

        # Attempt to read the local LICENSE file
        try:
            logger.info(f"Trying to read the local file at {license_local_path}")
            with open(license_local_path, "r", encoding="utf-8") as file:
                license_content = file.read()
                logger.info("Successfully read the local LICENSE file")
        except FileNotFoundError:
            logger.warning(f"Local LICENSE file not found at {license_local_path}")
            return "LICENSE file not found", 404

        # Render the content as plain text
        return render_template("plain_text.html", content=license_content)

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
