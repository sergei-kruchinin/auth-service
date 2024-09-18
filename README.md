# Auth Service

Auth Service is a robust and modular authentication and authorization system built with Flask. It supports traditional authentication as well as OAuth authentication (e.g., Yandex). The service uses JWT for token handling and includes user management functionality.

## Table of Contents

- [Features](#features)
- [Getting Started](#getting-started)
- [Project Structure](#project-structure)
- [Configuration](#configuration)
- [Usage](#usage)
- [Endpoints](#endpoints)
- [Error Handling](#error-handling)
- [License](#license)

## Features

- User Authentication with login and password
- OAuth Authentication (Yandex)
- JWT Token Generation and Validation
- User Creation and Listing
- Token Blacklisting
- Comprehensive Error Handling
- Extensible and Modular Architecture

## Getting Started

### Prerequisites

- Python 3.8+
- Flask
- SQLAlchemy
- Redis
- Requests
- Pydantic
- Other dependencies listed in `requirements.txt`

### Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/sergei-kruchinin/flask-auth-service.git
    cd flask-auth-service
    ```

2. Create a virtual environment and activate it:
    ```sh
    python3 -m venv .venv
    source .venv/bin/activate  # On Windows use `.venv\Scripts\activate`
    ```
   
3. Install Redis 
   ```shell
    sudo apt install redis redis-server redis-tools -y  # for debian like os
    ```

4. Install the dependencies:
    ```sh
    pip3 install -r requirements.txt
    ```
   
5.Configure your environment variables in a `.env` file:
```plaintext
AUTH_SECRET=YOUR_SECRET_KEY
ACCESS_EXPIRES_SECONDS=600
REFRESH_EXPIRES_SECONDS=1209600
API_DOMAIN=your_domain
YANDEX_ID=YOUR_YANDEX_CLIENT_ID
YANDEX_SECRET=YOUR_YANDEX_CLIENT_SECRET
```

### Running the Application

1. Initialize the database:
    ```sh
    python3 create_db_once.py
    ```

2. Start the Flask application:
    ```sh
    export PYTHONPATH=.
    python3 flask_app/app.py
    ```

## Project Structure

```plaintext
flask_auth_service/
├── core/
│   ├── __init__.py
│   ├── models.py
│   ├── token_service.py
│   ├── password_hash.py
│   ├── exceptions.py
│   ├── yandex_oauth.py
│   └── schemas.py
├── flask_app/
│   ├── app.py
│   ├── error_handlers.py
│   └── routes/
│       ├── __init__.py
│       ├── auth.py
│       ├── dependencies.py
│       └── front_emu.py
├── templates/
│   ├── auth_yandex.html
│   └── yandex_callback.html
├── config/
│   └── logger_config.py
├── create_db_once.py
├── requirements.txt
├── .env
├── LICENSE
└── README.md
```

## Configuration

Environment variables are used to configure the service. Key variables include:

- `AUTH_SECRET`: Secret key used for JWT encoding and decoding.
- `ACCESS_EXPIRES_SECONDS`: Expiration time for JWT access tokens in seconds. 
- `REFRESH_EXPIRES_SECONDS`: Expiration time for JWT refresh tokens in seconds. 
- `API_DOMAIN`: Domain of your web app.
- `YANDEX_ID`: Yandex OAuth client ID.
- `YANDEX_SECRET`: Yandex OAuth client secret.

## Usage

### User Authentication

1. **Login**: Authenticate a user with login and password.
    ```sh
    POST /auth
    {
        "login": "user_login",
        "password": "user_password"
    }
    ```

2. **Yandex OAuth**: Authenticate using Yandex OAuth.
    ```sh
    GET /auth/yandex/by_code 
    ```
    to get json with iframe_uri
    or
    ```sh
    GET /auth/yandex/by_code.html 
    ```
    
    to get a html page with link to yandex oauth page with your yandex client id (YOUR_YANDEX_ID).
    After granting authentication on yandex page it will redirect you to page 
    `/auth/yandex/callback?code=your_auth_code`
    which gives you auth token. If it's the first authorization user will be crated automatically.

### User Management

1. **Create User**: Create a new user (admin only).
    ```sh
    POST /users
    {
        "login": "new_user",
        "first_name": "First",
        "last_name": "Last",
        "password": "password",
        "is_admin": false
    }
    ```

2. **List Users**: Get a list of all users (admin only).
    ```sh
    GET /users
    ```

### Token Management

1. **Verify Token**: Verify a JWT token.
    ```sh
    POST /verify
    Headers: Authorization: Bearer <token>
    ```

2. **Logout**: Invalidate a JWT token.
    ```sh
    POST /logout
    Headers: Authorization: Bearer <token>
    ```

## Endpoints

- `POST /auth`: Authenticate user with login and password.
- `GET /auth/yandex/by_code`: Get the yandex oauth uri with Yandex client ID.
- `GET /auth/yandex/callback`: Handle Yandex OAuth callback.
- `POST /verify`: Verify JWT token.
- `POST /logout`: Invalidate JWT token.
- `POST /users`: Create a new user (admin).
- `GET /users`: List all users (admin).

## Error Handling

Errors are handled consistently across the service. Custom exceptions are defined in `auths/exceptions.py` and registered in `auths/error_handlers.py`.

## Other Notices

Blacklist of revoked tokens stored in redis.  
Refresh tokens still in development.
## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.


