# core > yandex_oauth.py

import base64
import requests
import os
from pydantic import ValidationError
import logging

from .schemas import YandexUserInfo, OAuthUserCreateSchema

logger = logging.getLogger(__name__)


class YandexOAuthService:
    """Service for handling Yandex OAuth operations."""

    @staticmethod
    def get_token_from_code(auth_code: str) -> str:
        """
        Exchange authorization code for access token from Yandex.

        Args:
            auth_code (str): Authorization code received from Yandex.

        Returns:
            str: Access token received from Yandex.

        Raises:
            requests.exceptions.RequestException: If there's an error during the request.
        """

        logger.debug("Attempting to exchange auth code for token")
        yandex_url = 'https://oauth.yandex.ru/token'
        client_id = os.getenv('YANDEX_ID')
        client_secret = os.getenv('YANDEX_SECRET')
        client_id_sec = f'{client_id}:{client_secret}'
        client_id_sec_base64_encoded = base64.b64encode(client_id_sec.encode()).decode()
        headers = {'Authorization': f'Basic {client_id_sec_base64_encoded}'}
        params = {'grant_type': 'authorization_code', 'code': auth_code}
        try:
            response = requests.post(yandex_url, headers=headers, data=params)
            response.raise_for_status()
            logger.info("Successfully received access token")
        except requests.exceptions.RequestException as e:
            logger.error(f"Error while exchanging code for token: {str(e)}")
            raise

        return response.json().get('access_token')

    @staticmethod
    def get_user_info(access_token: str) -> YandexUserInfo:
        """
        Fetch user info from Yandex using access token.

        Args:
            access_token (str): Access token received from Yandex.

        Returns:
            YandexUserInfo: Parsed user info.

        Raises:
            requests.exceptions.RequestException: If there's an error during the request.
            ValidationError: If the retrieved user info is invalid.
        """
        logger.debug("Fetching user info from Yandex")
        headers = {'Authorization': f'OAuth {access_token}'}
        yandex_url = 'https://login.yandex.ru/info'

        try:
            response = requests.get(yandex_url, headers=headers)
            response.raise_for_status()
            logger.info("Successfully retrieved user info")
        except requests.exceptions.RequestException as e:
            logger.error(f"Error while fetching user info: {str(e)}")
            raise

        raw_user_info = response.json()

        try:
            yandex_user_info = YandexUserInfo(**raw_user_info)
            logger.info("User info parsed successfully")
        except ValidationError as e:
            logger.error(f"Error parsing user info: {str(e)}")
            raise

        return yandex_user_info

    @staticmethod
    def yandex_user_info_to_oauth(user_info: YandexUserInfo) -> OAuthUserCreateSchema:
        """
        Convert Yandex user info to OAuth schema.

        Args:
            user_info (YandexUserInfo): User info retrieved from Yandex.

        Returns:
            OAuthUserCreateSchema: Converted user info in OAuth schema format.
        """
        logger.debug(
            f"Converting Yandex user info to OAuth schema for user {user_info.first_name} {user_info.last_name}")
        oauth_user_data = OAuthUserCreateSchema(
            first_name=user_info.first_name,
            last_name=user_info.last_name,
            is_admin=False,
            source='yandex',
            oa_id=user_info.id)
        logger.info("Conversion to OAuth schema successful")
        return oauth_user_data
