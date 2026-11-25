import re


def validate_client_credentials_filter_policy(request, context, grant, **kwargs):
    # Get the client data from the request
    requested_scopes = request["scope"]
    client_id = request.get("client_id")

    # Get the client data from the context
    client_data = context.cdb.get(client_id, {})
    allowed_scopes = client_data.get("allowed_scopes", [])
    claim_rules = client_data.get("claim_rules", {})
    claim_name = claim_rules.get("claim_name", [])
    require_scopes = claim_rules.get("require_scopes", [])
    allowed_values = claim_rules.get("allowed_values", [])

    if (
        "scope" not in request
        or not claim_rules
        or not require_scopes
        or not allowed_values
        or not any(scope in require_scopes for scope in requested_scopes)
    ):
        return {}

    # Keep scopes that are allowed
    scopes_req_allowed = [
        scope
        for scope in requested_scopes
        if scope in allowed_scopes
    ]
    if not scopes_req_allowed:
        return {}

    # Keep values (based on scopes) that are allowed
    claim_values = [
        scope
        for value_pattern in allowed_values
        for scope in scopes_req_allowed
        if re.match(value_pattern, scope)
    ]
    if not claim_values:
        return {}

    # Set the appropriate claim values
    claim = {claim_name: claim_values}
    grant.claims["custom_attributes"] = claim

    return claim
