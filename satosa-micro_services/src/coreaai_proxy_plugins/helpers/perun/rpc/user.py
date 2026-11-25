from .errors import Error


AM_GET_ATTR = "attributesManager/getAttribute"
AM_SET_ATTR = "attributesManager/setAttribute"

AM_GET_ATTRS = "attributesManager/getAttributes"
AM_SET_ATTRS = "attributesManager/setAttributes"

UM_ANON_USER = "usersManager/anonymizeUser"

UM_GET_USER = "usersManager/getUserByExtSourceNameAndExtLogin"


def get_attr(client, user_id, attribute_name):
    parameters = {"user": user_id, "attributeName": attribute_name}
    response = client.post(url=AM_GET_ATTR, json=parameters)
    response_json = response.json()
    if "errorId" in response_json:
        raise Error(response_json)
    return response_json


def get_attrs(client, user_id, attribute_names):
    parameters = {"user": user_id, "attrNames": attribute_names}
    response = client.post(url=AM_GET_ATTRS, json=parameters)
    response_json = response.json()
    if "errorId" in response_json:
        raise Error(response_json)
    return response_json


def set_attr(client, ext_user_id, attribute, value):
    attribute["value"] = value
    parameters = {"user": ext_user_id, "attribute": attribute}
    response = client.post(url=AM_SET_ATTR, json=parameters)
    response_json = response.json()
    if response_json is not None:
        raise Error(response_json)
    return attribute


def set_attrs(client, ext_user_id, attributes):
    parameters = {"user": ext_user_id, "attributes": attributes}
    response = client.post(url=AM_SET_ATTRS, json=parameters)
    response_json = response.json()
    if response_json is not None:
        raise Error(response_json)
    return attributes


def anonymize(client, ext_user_id):
    parameters = {"user": ext_user_id, "force": True}
    response = client.post(url=UM_ANON_USER, json=parameters)
    response_json = response.json()
    if response_json is not None:
        raise Error(response_json)
    return response_json


def get_user(client, extSourceName, extLogin):
    parameters = {"extSourceName": extSourceName, "extLogin": extLogin}
    response = client.post(url=UM_GET_USER, json=parameters)
    response_json = response.json()
    if "errorId" in response_json:
        raise Error(response_json)
    return response_json
