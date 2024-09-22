# fastapi_app > routes > front_emu.py

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from .dependencies import get_yandex_uri
import requests
import markdown
import os
import logging

logger = logging.getLogger(__name__)

templates = Jinja2Templates(directory="../templates")

def register_routes(router: APIRouter):
    front_emu_router = APIRouter()

    @front_emu_router.get("/", response_class=HTMLResponse)
    async def display_readme(request: Request):
        """
        Default route that fetches and displays the README.md file as HTML.
        """
        logger.info("Root route called")

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
                raise HTTPException(status_code=response.status_code, detail="Failed to fetch the README.md file")

            md_content = response.text

        logger.info("Converting Markdown to HTML")
        html_content = markdown.markdown(md_content)

        logger.info("Rendering template")
        return templates.TemplateResponse("readme_md.html", {"request": request, "html_content": html_content})

    @front_emu_router.get("/LICENSE", response_class=HTMLResponse)
    async def display_license(request: Request):
        """
        Route that fetches and displays the LICENSE file as plain text.
        """
        logger.info("License route called")

        license_local_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "LICENSE")

        # Attempt to read the local LICENSE file
        try:
            logger.info(f"Trying to read the local file at {license_local_path}")
            with open(license_local_path, "r", encoding="utf-8") as file:
                license_content = file.read()
                logger.info("Successfully read the local LICENSE file")
        except FileNotFoundError:
            logger.warning(f"Local LICENSE file not found at {license_local_path}")
            raise HTTPException(status_code=404, detail="LICENSE file not found")

        return templates.TemplateResponse("plain_text.html", {"request": request, "content": license_content})

    @front_emu_router.get("/auth/yandex/by_code.html", response_class=HTMLResponse)
    async def auth_yandex_by_code_html():
        """
        Route for displaying the link to Yandex OAuth authorization page.
        """
        logger.info("Yandex OAuth by code HTML called")
        iframe_uri = get_yandex_uri()
        return HTMLResponse(content=f'<a href="{iframe_uri}">{iframe_uri}</a>')

    @front_emu_router.get("/auth/yandex.html", response_class=HTMLResponse)
    async def auth_yandex_html(request: Request):
        """
        Route for displaying the Yandex OAuth authorization page.
        """
        logger.info("Yandex OAuth HTML called")
        yandex_id = os.getenv('YANDEX_ID')
        api_domain = os.getenv('API_DOMAIN')
        redirect_uri = f"https://{api_domain}/auth/yandex/callback.html"
        callback_uri = f"https://{api_domain}/auth/yandex/callback"
        return templates.TemplateResponse("auth_yandex.html", {
            "request": request,
            "yandex_id": yandex_id,
            "api_domain": api_domain,
            "redirect_uri": redirect_uri,
            "callback_uri": callback_uri
        })

    @front_emu_router.get("/auth/yandex/callback.html", response_class=HTMLResponse)
    async def auth_yandex_callback_html(request: Request):
        """
        Route for handling Yandex OAuth callback and presenting a helper page.
        """
        logger.info("Yandex OAuth callback HTML called")
        api_domain = os.getenv('API_DOMAIN')
        callback_uri = f"https://{api_domain}/auth/yandex/callback.html"
        return templates.TemplateResponse("yandex_callback.html", {"request": request, "callback_uri": callback_uri})

    @front_emu_router.get("/framework.html", response_class=HTMLResponse)
    def framework_htm():
        """
        Route for displaying the name of using framework.

        Method: GET

        Returns:
        200: The name of framework
        """
        logger.info("The name of framework called")
        return HTMLResponse(content=f'Fastapi')

    router.include_router(front_emu_router, prefix="")
    print(f"FrontEmu routes registered: {[route.path for route in router.routes if hasattr(route, 'path')]}")
