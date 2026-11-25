from uuid import uuid4

from tests.utils import is_valid_uuid


def test_get_insert_cuid(test_app, api_key):
    iuids = [f"{uuid4()}@idp-scope" for _ in range(2)]
    response = test_app.post(
        "/cuid/",
        headers={"access_token": api_key},
        json=iuids,
    )

    response_body = response.json()

    assert response.status_code == 201
    assert "cuid" in response_body
    generated_cuid = response_body["cuid"]
    assert is_valid_uuid(generated_cuid) is True

    new_iuid = str(uuid4())

    response = test_app.post(
        "/cuid/",
        headers={"access_token": api_key},
        json=iuids[:] + [new_iuid],
    )
    response_body = response.json()
    assert response.status_code == 200
    assert "cuid" in response_body
    new_cuid = response_body["cuid"]
    assert new_cuid == generated_cuid

    response = test_app.post(
        "/cuid/",
        headers={"access_token": api_key},
        json=[new_iuid],
    )
    response_body = response.json()
    assert response.status_code == 200
    assert "cuid" in response_body
    new_cuid = response_body["cuid"]
    assert new_cuid == generated_cuid
