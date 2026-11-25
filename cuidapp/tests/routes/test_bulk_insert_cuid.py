def test_empty_list(test_app, api_key):
    response = test_app.post(
        "/batch/cuids/",
        headers={"access_token": api_key},
        json={"records": []},
    )

    assert response.status_code == 200
    assert response.json() == {"results": []}


def test_bulk_insert(test_app, api_key):
    response = test_app.post(
        "/batch/cuids/",
        headers={"access_token": api_key},
        json={
            "records": [
                {
                    "cuid": "cuid-bulk-1",
                    "iuids": [
                        "iuid-bulk-1-1",
                        "iuid-bulk-1-2",
                        "iuid-bulk-1-3",
                    ],
                },
                {
                    "cuid": "cuid-bulk-2",
                    "iuids": [
                        "iuid-bulk-2-1",
                        "iuid-bulk-2-2",
                        "iuid-bulk-2-3",
                    ],
                },
            ]
        },
    )

    assert response.status_code == 200
    response_json = response.json()["results"]
    assert len(response_json) == 2
    assert response_json[0]["cuid"] == "cuid-bulk-1"
    assert response_json[0]["iuids"] == [
        "iuid-bulk-1-1",
        "iuid-bulk-1-2",
        "iuid-bulk-1-3",
    ]
    assert response_json[1]["cuid"] == "cuid-bulk-2"
    assert response_json[1]["iuids"] == [
        "iuid-bulk-2-1",
        "iuid-bulk-2-2",
        "iuid-bulk-2-3",
    ]


def test_repeated_cuid(test_app, api_key):
    response = test_app.post(
        "/batch/cuids/",
        headers={"access_token": api_key},
        json={
            "records": [
                {
                    "cuid": "duplicate-cuid",
                    "iuids": [
                        "random1",
                    ],
                },
                {
                    "cuid": "duplicate-cuid",
                    "iuids": ["random2"],
                },
            ]
        },
    )

    assert response.status_code == 400
    assert response.json() == {"detail": "Duplicate CUID in request"}
