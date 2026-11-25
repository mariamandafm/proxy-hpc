import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import main
from settings import get_settings


@pytest.fixture
def setup_database():
    engine = create_engine(get_settings().db_connection_url)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


@pytest.fixture
def session(setup_database):
    session = setup_database
    yield session


@pytest.fixture
def test_app():
    with TestClient(main.app) as test_client:
        yield test_client


@pytest.fixture(scope="module")
def api_key():
    return get_settings().api_keys[0]
