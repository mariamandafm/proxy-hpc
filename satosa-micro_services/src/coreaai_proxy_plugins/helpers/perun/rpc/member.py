from .errors import Error


MM_CREATE_MEMBER = "membersManager/createMember"
MM_GET_MEMBER_BY_ES_NAME_LOGIN = "membersManager/getMemberByExtSourceNameAndExtLogin"
MM_SET_STATUS = "membersManager/setStatus"


def prepare_candidate(
    ext_user_login, ext_source, first_name, last_name, user_attrs=None
):
    value = {
        "firstName": first_name,
        "lastName": last_name,
        "userExtSource": {
            "login": ext_user_login,
            "extSource": ext_source,
        },
        "attributes": user_attrs or {},
    }
    return value


def create(client, vo_id, candidate):
    parameters = {"vo": vo_id, "candidate": candidate}
    response = client.post(url=MM_CREATE_MEMBER, json=parameters)
    response_json = response.json()
    if "errorId" in response_json:
        if response_json.get("name") == "AlreadyMemberException":
            return response_json["member"]
        raise Error(response_json)
    return response_json


def set_membership_status(client, member_id):
    parameters = {"member": member_id, "status": "VALID"}
    response = client.post(url=MM_SET_STATUS, json=parameters)
    response_json = response.json()
    if "errorId" in response_json:
        raise Error(response_json)
    return response_json
