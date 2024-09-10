# auths > yandex_html.py

# temporary realization
# js code by yandex to OAuth 2.0
# API callback called without any page modification

def auth_yandex_html_code(yandex_id, api_domain, redirect_uri, callback_uri):
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


def auth_yandex_callback_html_code(callback_uri):
    html_code = f'''
<html>
 <head>
   <script src="https://yastatic.net/s3/passport-sdk/autofill/v1/sdk-suggest-token-with-polyfills-latest.js"></script>
</head>
<body>
   <script>
      window.onload = function() {{
         window.YaSendSuggestToken("{callback_uri}", {{
            
         }});
      }};
   </script>
'''
    return html_code
