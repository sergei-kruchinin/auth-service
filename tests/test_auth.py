import pytest
import requests
from core.schemas import ManualUserCreateSchema, AuthRequest
from core.models import Base, engine, User
from sqlalchemy.orm import sessionmaker


BASE_URL = "http://localhost:5000"


SessionLocal = sessionmaker(bind=engine)


@pytest.fixture(scope="module", autouse=True)
def setup_database():
    Base.metadata.drop_all(bind=engine)  # Drop all tables (to clear db before tests)
    Base.metadata.create_all(bind=engine)  # Create all tables
    session = SessionLocal()

    # Создаем тестового администратора
    admin_data = ManualUserCreateSchema(
        username='admin',
        first_name='admin',
        last_name='system',
        password='password',
        is_admin=True,
        source='manual',
        oa_id=None
    )
    User.create_with_check(session, admin_data)
    session.commit()
    session.close()
    yield
    # Do like create_db_once.py for manual test
    Base.metadata.drop_all(bind=engine)  # Delete all tables after tests
    Base.metadata.create_all(bind=engine)  # Create all tables
    User.create_with_check(session, admin_data)  # Return admin for manual tests


@pytest.fixture(scope="module")
def get_admin_token():
    url = f"{BASE_URL}/auth"
    payload = {
        "username": "admin",
        "password": "password"
    }
    response = requests.post(url, json=payload)
    assert response.status_code == 200, f"Expected status code 200, but got {response.status_code}"
    data = response.json()
    assert 'access_token' in data, "Access token not found"
    return data['access_token']


def test_create_user(get_admin_token):
    url = f"{BASE_URL}/users"
    payload = {
        "username": "testuser",
        "first_name": "Test",
        "last_name": "User",
        "password": "password",
        "is_admin": False,
        "source": "manual",
        "oa_id": None
    }

    headers = {
        "Authorization": f"Bearer {get_admin_token}"  # Using admin token
    }

    response = requests.post(url, json=payload, headers=headers)
    assert response.status_code == 201, f"Expected status code 201, but got {response.status_code}"
    data = response.json()
    assert data['success'] is True, "User creation failed"


@pytest.fixture
def get_user_token():
    url = f"{BASE_URL}/auth"
    payload = {
        "username": "testuser",
        "password": "password"
    }
    response = requests.post(url, json=payload)
    assert response.status_code == 200, f"Expected status code 200, but got {response.status_code}"
    data = response.json()
    assert 'access_token' in data, "Access token not found"
    return data['access_token']


def test_authenticate_user(get_user_token):
    # Use fixture to check validity user's token
    assert get_user_token is not None, "User access token not obtained"


def test_verify_token(get_user_token):
    url = f"{BASE_URL}/verify"
    headers = {
        "Authorization": f"Bearer {get_user_token}"  # Using token, got in get_user_token
    }
    response = requests.post(url, headers=headers)
    assert response.status_code == 200, f"Expected status code 200, but got {response.status_code}"
    data = response.json()
    assert 'success' in data, "Verification status not found"
    assert data['success'] is True, "Token verification failed"


def test_logout(get_user_token):
    url = f"{BASE_URL}/logout"
    headers = {
        "Authorization": f"Bearer {get_user_token}"  # Using token, got in get_user_token
    }
    response = requests.post(url, headers=headers)
    assert response.status_code == 200, f"Expected status code 200, but got {response.status_code}"
    data = response.json()
    assert data['success'] is True, "Logout failed"


def test_get_users(get_admin_token):
    url = f"{BASE_URL}/users"
    headers = {
        "Authorization": f"Bearer {get_admin_token}"  # Using admin token
    }
    response = requests.get(url, headers=headers)
    assert response.status_code == 200, f"Expected status code 200, but got {response.status_code}"
    data = response.json()
    assert isinstance(data['users'], list), "Expected data to be a list"
    assert len(data['users']) > 0, "Expected at least one user"

