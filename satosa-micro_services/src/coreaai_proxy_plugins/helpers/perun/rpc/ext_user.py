from .errors import Error


AM_GET_ATTR = "attributesManager/getAttribute"
AM_SET_ATTR = "attributesManager/setAttribute"

AM_GET_ATTRS = "attributesManager/getAttributes"
AM_SET_ATTRS = "attributesManager/setAttributes"

UM_GET_UES_BY_UNIQUE_AV = "usersManager/getUserExtSourceByUniqueAttributeValue"
UM_GET_UES_BY_LOGIN_NAME = "usersManager/getUserExtSourceByExtLoginAndExtSourceName"


def get_by_uniq_attr(client, attribute_name, attribute_value):
    parameters = {"attributeName": attribute_name, "attributeValue": attribute_value}
    response = client.post(url=UM_GET_UES_BY_UNIQUE_AV, json=parameters)
    response_json = response.json()
    if "errorId" in response_json:
        raise Error(response_json)
    return response_json


# XXX This is not working expected; it will only work with the initially-set IUID
# XXX Additional IUIDs will return error
# XXX Updated IUIDs will return error
# XXX The initial IUID will work even if it is not listed as a value..
def get_by_login(client, ext_source_name, ext_source_login):
    """
    Retrieves the external user identity matching the source and the login.

    :param ext_source_name: the name of the issuer
    :param ext_source_login: the identifier of the identity; one of the IUIDs.
    :return: external identity object in json
    """
    parameters = {"extSourceName": ext_source_name, "extSourceLogin": ext_source_login}
    response = client.post(url=UM_GET_UES_BY_LOGIN_NAME, json=parameters)
    response_json = response.json()
    if "errorId" in response_json:
        raise Error(response_json)
    return response_json


def get_attr(client, ext_user_id, attribute_name):
    parameters = {"userExtSource": ext_user_id, "attributeName": attribute_name}
    response = client.post(url=AM_GET_ATTR, json=parameters)
    response_json = response.json()
    if "errorId" in response_json:
        raise Error(response_json)
    return response_json


def get_attrs(client, ext_user_id, attribute_names):
    parameters = {"userExtSource": ext_user_id, "attrsNames": attribute_names}
    response = client.post(url=AM_GET_ATTRS, json=parameters)
    response_json = response.json()
    if "errorId" in response_json:
        raise Error(response_json)
    return response_json


def set_attr(client, ext_user_id, attribute, value):
    attribute["value"] = value
    parameters = {"userExtSource": ext_user_id, "attribute": attribute}
    response = client.post(url=AM_SET_ATTR, json=parameters)
    response_json = response.json()
    if response_json is not None:
        raise Error(response_json)
    return attribute


def set_attrs(client, ext_user_id, attributes):
    parameters = {"userExtSource": ext_user_id, "attributes": list(attributes.values())}
    response = client.post(url=AM_SET_ATTRS, json=parameters)
    response_json = response.json()
    if response_json is not None:
        raise Error(response_json)
    return attributes
