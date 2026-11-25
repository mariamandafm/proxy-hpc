from database.models import CommunityUserIdentifier, InternalUserIdentifier


def test_empty_strings(test_app, api_key):
    response = test_app.post(
        "/utils/cuids/migrate/",
        headers={"access_token": api_key},
        json={
            "source_cuid": "",
            "target_cuid": "",
        },
    )

    # empty json not allowed
    assert response.status_code == 404


def test_moving(test_app, api_key, session):
    session.add_all(
        [
            CommunityUserIdentifier(
                id=200,
                cuid="test-cuid3",
            ),
            CommunityUserIdentifier(
                id=201,
                cuid="test-cuid4",
            ),
        ]
    )

    session.add_all(
        [
            InternalUserIdentifier(
                iuid="test-iuid3",
                cuid_id=200,
            ),
            InternalUserIdentifier(
                iuid="test-iuid4",
                cuid_id=201,
            ),
        ]
    )

    session.commit()

    response = test_app.post(
        "/utils/cuids/migrate/",
        headers={"access_token": api_key},
        json={
            "source_cuid": "test-cuid3",
            "target_cuid": "test-cuid4",
        },
    )

    assert response.status_code == 200
    assert response.json() == {"success": True}

    assert (
        session.get(
            CommunityUserIdentifier,
            ident=200,
        ).internal_user_identifiers
        == []
    )

    assert [
        item.iuid
        for item in session.get(
            CommunityUserIdentifier,
            ident=201,
        ).internal_user_identifiers
    ] == ["test-iuid3", "test-iuid4"]
