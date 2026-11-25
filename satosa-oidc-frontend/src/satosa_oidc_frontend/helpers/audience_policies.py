import logging

import satosa.logging_util as lu

from idpyoidc.message.oauth2 import TokenIntrospectionRequest
from idpyoidc.message.oauth2 import RefreshAccessTokenRequest
from idpyoidc.message.oauth2 import AuthorizationRequest


logger = logging.getLogger(__name__)


def simpleLogger(request, context, client_id, client_info, audience, grant, **kwargs):
    msg = f"Client Id: {request['client_id']}, Requested Resources: {request.get('resource', '')}"
    logline = lu.LOG_FMT.format(id=lu.get_session_id(context), message=msg)
    logger.info(logline)


def setTokenOwnerAsGrantResource(request, context, client_id, client_info, audience, grant, **kwargs):
    if not isinstance(request, AuthorizationRequest):
        return

    resources = grant.resources or []
    if client_id not in resources:
        resources.append(client_id)
    grant.resources = resources


def setTokenOwnerAsReqResource(request, context, client_id, client_info, audience, grant, **kwargs):
    if not isinstance(request, AuthorizationRequest):
        return

    resources = request["resource"] or []
    if client_id not in resources:
        resources.append(client_id)
    request["resource"] = resources


def checkIntrospectionRespByAud(request, context, client_id, client_info, audience, grant, **kwargs):
    if not isinstance(request, TokenIntrospectionRequest):
        return

    is_client_owner_of_token = client_id == grant.authorization_request.get("client_id")
    is_client_intended_aud = client_id in audience
    if not is_client_owner_of_token and not is_client_intended_aud:
        request['error'] = "audience_policy_error"
        request['error_description'] = "No resource in the request"


def checkIntrospectionFail(request, context, client_id, client_info, audience, grant, **kwargs):
    if not isinstance(request, TokenIntrospectionRequest):
        return

    is_client_intended_aud = client_id in audience
    if not is_client_intended_aud:
        request['error'] = "audience_policy_error"
        request['error_description'] = "No resource in the request"


def checkAudienceExist(request, context, client_id, client_info, audience, grant, **kwargs):
    if not isinstance(request, TokenIntrospectionRequest):
        return

    is_client_owner_of_token = client_id == grant.authorization_request.get("client_id")
    is_client_intended_aud = client_id in audience
    if not is_client_owner_of_token and not is_client_intended_aud:
        request['error'] = "audience_policy_error"
        request['error_description'] = "No resource in the request"


def checkRefreshTokenRequest(request, context, client_id, client_info, audience, grant, **kwargs):
    if not isinstance(request, RefreshAccessTokenRequest):
        return

    is_client_owner_of_token = client_id == grant.authorization_request.get("client_id")
    is_client_intended_aud = client_id in audience
    if not is_client_owner_of_token and not is_client_intended_aud:
        request['error'] = "audience_policy_error"
        request['error_description'] = "client3 resource not in the request"


def validateResources(request, context, client_id, client_info, audience, grant, **kwargs):
    """
    Validates that the request contains at least one resource.

    Parameters:
        request (dict): The client request containing 'resource'.

    Raises:
        ValidationError: If no resources are provided.
    """
    if not request.get('resource'):
        request['error'] = "audience_policy_error"
        request['error_description'] = "No resource in the request"
