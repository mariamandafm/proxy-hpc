import pytest
from satosa.internal import InternalData


@pytest.fixture
def default_data():
    return InternalData(
        attributes={"mail": "test1@test.com"},
    )
