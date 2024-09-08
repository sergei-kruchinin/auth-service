import base64
import requests
import os
from .schemas import YandexUserInfo, OAuthUserCreateSchema


class YandexOAuthService:
    @staticmethod
    def get_token_from_code(auth_code: str) -> str:
        yandex_url = 'https://oauth.yandex.ru/token'
        client_id = os.getenv('YANDEX_ID')
        client_secret = os.getenv('YANDEX_SECRET')
        client_id_sec = f'{client_id}:{client_secret}'
        client_id_sec_base64_encoded = base64.b64encode(client_id_sec.encode()).decode()
        headers = {'Authorization': f'Basic {client_id_sec_base64_encoded}'}
        params = {'grant_type': 'authorization_code', 'code': auth_code}
        response = requests.post(yandex_url, headers=headers, data=params)
        response.raise_for_status()
        return response.json().get('access_token')

    @staticmethod
    def get_user_info(access_token: str) -> YandexUserInfo:
        headers = {'Authorization': f'OAuth {access_token}'}
        yandex_url = 'https://login.yandex.ru/info'
        response = requests.get(yandex_url, headers=headers)
        response.raise_for_status()
        raw_user_info = response.json()
        yandex_user_info = YandexUserInfo(**raw_user_info)
        return yandex_user_info

    @staticmethod
    def yandex_user_info_to_oauth_user_create_schema(user_info: YandexUserInfo) -> OAuthUserCreateSchema:
        oauth_user_data = OAuthUserCreateSchema(
            first_name=user_info.first_name,
            last_name=user_info.last_name,
            is_admin=False,
            source='yandex',
            oa_id=user_info.id)

        return oauth_user_data
