from .errors import Error


ES_TYPE_IDP = "cz.metacentrum.perun.core.impl.ExtSourceIdp"

ESM_CREATE_ES = "extSourcesManager/createExtSource"
ESM_GET_ES_BY_NAME = "extSourcesManager/getExtSourceByName"


def get(client, ext_source_name):
    parameters = {"name": ext_source_name}
    response = client.post(url=ESM_GET_ES_BY_NAME, json=parameters)
    response_json = response.json()
    if "errorId" in response_json:
        raise Error(response_json)
    return response_json


def create(client, ext_source_name):
    parameters = {"name": ext_source_name, "type": ES_TYPE_IDP}
    response = client.post(url=ESM_CREATE_ES, json=parameters)
    response_json = response.json()
    if "errorId" in response_json:
        raise Error(response_json)
    return response_json
