import hashlib
import json
import os
from functools import wraps

from flask import request

from . import app
from .models import Users, Blacklist
import requests

# decorator for token verification
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        authorization_header = request.headers.get('authorization')

        # fix bug where no token
        if authorization_header is None:
            return {'success': False, 'message': 'header not specified'}
        token = authorization_header.replace("Bearer ", "")
        verification = Users.auth_verify(token)
        return f(token, verification, *args, **kwargs)

    return decorated


# if invalid json, return json error, not html
@app.errorhandler(400)
def bad_request():
    return {'success': False, 'message': 'Invalid JSON sent'}, 400

# TODO: add HTTP codes to routes' return


@app.route("/hello", methods=["POST"])
def hello():
    # TODO: remove this function -- it was just for me
    # TODO: before: make the wellcome function. From jwt token reads th info about user and is_admin status
    # on the verify base

    json_data = request.get_json()
    user_name = json_data.get("user_name")
    return {'success': True, 'user_name': user_name}


@app.route("/hello", methods=["GET"])
def hello_get():
    return {'success': True, 'message': 'hello script'}


@app.route("/", methods=["GET"])
def site_root():
    return '<html><body>hello world</body></html>'




# API Route dummy for yandex OAuth 2.0
@app.route("/auth/yandex/callback", methods=["POST","GET"])
def auth_yandex_post():
    print('Callback!')

    if request.method == 'POST':
        token = request.json.get('token')
    else:
        token = request.args.get('token')


    print(token)

    headers = {'Authorization': f'OAuth {token}'}
    yandex_url = 'https://login.yandex.ru/info'

    # Делаем запрос к API Яндекса для получения информации о пользователе
    response = requests.get(yandex_url, headers=headers)
    print(response.request.url)
    print(response.request.headers)
    print('CHecking')
    print(response.status_code)
    if response.status_code == 200:
        user_info = response.json()
        user_email = user_info.get('default_email')  # Получаем email пользователя
        user_full_name = user_info.get('real_name')  # Получаем фио пользователя
        return {'email': user_email, 'full_name': user_full_name}, 200

    return {'error': 'Unable to retrieve user data'}, 400






# TO DO  route to return path to open in iframe https://oauth.yandex.ru/authorize?client_id=
# &response_type=token&redirect_uri=https%3A%2F%2F{domain}%2Fauth%2Fyandex%2Fcallback
# widget_kind=button&
# suggest_hostname={domain}&
# et={what is the et?}&force_confirm=1

# DUMMY HTML for Oauth 2.0 Request
@app.route("/auth/yandex.html", methods=["GET"])
def auth_yandex_html():
    yandex_id = os.getenv('YANDEX_ID')
    yandex_secret = os.getenv('YANDEX_SECRET')
    api_domain = os.getenv('API_DOMAIN')
    redirect_uri = f"https://{api_domain}/auth/yandex/callback.html"
    callback_uri = f"https://{api_domain}/auth/yandex/callback"

    html_code = f'''
<html>
 <head>
 <script src="https://yastatic.net/s3/passport-sdk/autofill/v1/sdk-suggest-with-polyfills-latest.js"></script>
 </head>
<body>
<script>
window.YaAuthSuggest.init(
    {{
      client_id: "{yandex_id}",
      response_type: "token",
      redirect_uri: "{redirect_uri}"
    }},
    "https://{api_domain}",
    {{
      view: "button",
      parentId: "buttonContainerId",
      buttonSize: 'm',
      buttonView: 'main',
      buttonTheme: 'light',
      buttonBorderRadius: "0",
      buttonIcon: 'ya',
    }}
  )
  .then(({{handler}}) => handler())
  .then(data => {{
    // Отправляем POST запрос на свой сервер с токеном в теле запроса
    fetch("{callback_uri}", {{
      method: 'POST', 
      headers: {{
        'Content-Type': 'application/json',
      }},
      body: JSON.stringify({{token: data.access_token}})
    }})
    .then(response => response.json())
    .then(data => console.log('Success:', data))
    .catch((error) => console.log('Error:', error));
  }})
  .catch(error => console.log('Обработка ошибки', error))
</script>
'''
    return html_code

# HTML For callback proceed

@app.route("/auth/yandex/callback.html", methods=["GET"])
def auth_yandex_callback_html():
    yandex_id = os.getenv('YANDEX_ID')
    yandex_secret = os.getenv('YANDEX_SECRET')
    api_domain = os.getenv('API_DOMAIN')
    callback_uri = f"https://{api_domain}/auth/yandex/callback.html"

    html_code = f'''
<html>
 <head>
   <script src="https://yastatic.net/s3/passport-sdk/autofill/v1/sdk-suggest-token-with-polyfills-latest.js"></script>
</head>
<body>
   <script>
      window.onload = function() {{
         window.YaSendSuggestToken("{callback_uri}", {{
            "kek": true
         }});
      }};
   </script>
'''
    return html_code


# API Route for checking the user_id and user_secret
@app.route("/auth", methods=["POST"])
def auth():
    # get the user_id and secret from the client application
    json_data = request.get_json()
    user_name = json_data.get("login")
    user_secret_input = json_data.get("password")

    # fix bug if no login or password in json
    if user_name is None or user_secret_input is None:
        return {'success': False, 'message': 'login or password not specified'}

    # the user secret in the database is "hashed" with a one-way hash
    hash_object = hashlib.sha1(bytes(user_secret_input, 'utf-8'))
    hashed_user_secret = hash_object.hexdigest()

    # make a call to the model to authenticate
    authentication = Users.authenticate(user_name, hashed_user_secret)
    if not authentication:
        return {'success': False}
    else:
        return json.dumps(authentication)


# API route for verifying the token passed by API calls
@app.route("/verify", methods=["POST"])
@token_required
def verify(_, verification):
    # verify the token 
    return verification


# API route for token revocation
@app.route("/logout", methods=["POST"])
@token_required
def logout(token, verification):
    if verification.get('success') is False:  # if verifications return json data success 'll be Null
        message = verification.get('message')
        status = True
        # if already no valid nothing to do
    else:  # Auth succeed so adding to blacklist
        Blacklist.add_token(token)  # now it doesn't return True or False
        status = True
        message = 'Adding to blacklist '
    return {'success': status, 'message': message}

# TODO make a logout from all devices


# API route to create the new user
@app.route("/users", methods=["POST"])
@token_required
def users_create(_, verification):
    if verification.get("is_admin"):
        # get the client_id and secret from the client application
        json_data = request.get_json()
        user_name = json_data.get("login")
        user_secret_input = json_data.get("password")
        is_admin = json_data.get("is_admin")

        # the user secret in the database is "hashed" with a one-way hash
        hash_object = hashlib.sha1(bytes(user_secret_input, 'utf-8'))
        hashed_user_secret = hash_object.hexdigest()

        # make a call to the model to create user
        create_response = Users.create(user_name, hashed_user_secret, is_admin)
        return {'success': create_response}
    else:
        return {'success': False, 'message': 'Access Denied'}


# DUMMY for API route to delete user (if is_admin)
@app.route("/users", methods=["DELETE"])
@token_required
def users_delete():
    # not yet implemented
    return {'success': False}


# API route to get users list
@app.route("/users", methods=["GET"])
@token_required
def users_list(_, verification):
    if verification.get("is_admin"):
        return Users.list()
    else:
        return {'success': False, 'message': 'Access Denied'}
