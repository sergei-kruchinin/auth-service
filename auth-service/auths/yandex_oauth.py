# yandex_oauth.py

import base64
import requests
import os
from .schemas import YandexUserInfo, OAuthUserCreateSchema
from pydantic import ValidationError
import logging
logger = logging.getLogger(__name__)


class YandexOAuthService:
    @staticmethod
    def get_token_from_code(auth_code: str) -> str:
        logger.info("Attempting to exchange auth code for token")
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
        logger.info("Fetching user info from Yandex")
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
        logger.info(f"Converting Yandex user info to OAuth schema for user {user_info.first_name} {user_info.last_name}")
        oauth_user_data = OAuthUserCreateSchema(
            first_name=user_info.first_name,
            last_name=user_info.last_name,
            is_admin=False,
            source='yandex',
            oa_id=user_info.id)
        logger.info("Conversion to OAuth schema successful")
        return oauth_user_data
