from database.models import CommunityUserIdentifier, InternalUserIdentifier


def test_empty_list(test_app, api_key):
    response = test_app.post(
        "/utils/cuids/",
        headers={"access_token": api_key},
        json=[],
    )

    # empty json not allowed
    assert response.status_code == 422


def test_not_registered_list(test_app, api_key):
    response = test_app.post(
        "/utils/cuids/",
        headers={"access_token": api_key},
        json=["test-iuid"],
    )

    assert response.status_code == 200
    assert response.json() == {
        "__NOT_REGISTERED": ["test-iuid"],
    }


def test_mapping(test_app, api_key, session):
    session.add_all(
        [
            CommunityUserIdentifier(
                id=100,
                cuid="test-cuid1",
            ),
            CommunityUserIdentifier(
                id=101,
                cuid="test-cuid2",
            ),
        ]
    )

    session.add_all(
        [
            InternalUserIdentifier(
                iuid="test-iuid1",
                cuid_id=100,
            ),
            InternalUserIdentifier(
                iuid="test-iuid2",
                cuid_id=101,
            ),
        ]
    )

    session.commit()

    response = test_app.post(
        "/utils/cuids/",
        headers={"access_token": api_key},
        json=["test-iuid1", "test-iuid2", "test-iuid3"],
    )

    assert response.status_code == 200
    assert response.json() == {
        "test-cuid1": ["test-iuid1"],
        "test-cuid2": ["test-iuid2"],
        "__NOT_REGISTERED": ["test-iuid3"],
    }
