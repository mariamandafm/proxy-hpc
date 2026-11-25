"""
Grove SCIM API helper functions.

This module provides helper functions for interacting with Grove's SCIM 2.0 API,
following the same pattern as coreaai_proxy_plugins.helpers.perun.rpc.

Example usage:
    from coreaai_proxy_plugins.helpers.grove.scim import get_user, create_user, update_user

    # Get user by CUID
    user = get_user(client, cuid="user123")

    # Create new user
    user = create_user(
        client,
        username="user123",
        first_name="John",
        last_name="Doe",
        emails=["john.doe@example.org"]
    )

    # Update user attributes
    updated_user = update_user(
        client,
        user_id="user123",
        first_name="Jane"
    )
"""

from typing import List, Optional


class SCIMError(Exception):
    """Base exception for SCIM API errors."""
    def __init__(self, message, error_context=None):
        super().__init__(message)
        self.message = message
        self.error_context = error_context or {}


def get_user(client, cuid: str) -> Optional[dict]:
    """
    Get user by CUID (userName) from Grove.

    Args:
        client: HTTP client session (requests.Session)
        cuid: Community Unique Identifier (userName in Grove)

    Returns:
        User resource dict if found, None if not found

    Raises:
        SCIMError: On API errors (except 404)

    Example:
        user = get_user(client, cuid="user123")
        if user:
            print(f"Found user: {user['userName']}")
    """
    try:
        response = client.get(f"/scim/v2/Users/{cuid}")
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return None
        else:
            error_context = {
                "status_code": response.status_code,
                "cuid": cuid,
                "response": response.text
            }
            raise SCIMError(f"Failed to get user {cuid}", error_context)
    except SCIMError:
        raise
    except Exception as e:
        error_context = {"cuid": cuid, "exception": str(e)}
        raise SCIMError(f"Failed to get user {cuid}", error_context) from e


def create_user(
    client,
    username: str,
    first_name: str,
    last_name: str,
    emails: List[str],
    active: bool = True
) -> dict:
    """
    Create a new user in Grove.

    Args:
        client: HTTP client session (requests.Session)
        username: CUID to use as userName
        first_name: User's given name
        last_name: User's family name
        emails: List of email addresses (first will be marked as primary)
        active: Whether user account is active (default: True)

    Returns:
        Created user resource dict

    Raises:
        SCIMError: On API errors

    Example:
        user = create_user(
            client,
            username="user123",
            first_name="John",
            last_name="Doe",
            emails=["john.doe@example.org", "j.doe@institution.edu"]
        )
        print(f"Created user ID: {user['id']}")
    """
    # Build emails array - mark first as primary
    emails_data = []
    for idx, email in enumerate(emails):
        emails_data.append({
            "value": email,
            "primary": idx == 0
        })

    user_data = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": username,
        "name": {
            "givenName": first_name,
            "familyName": last_name
        },
        "emails": emails_data,
        "active": active
    }

    try:
        response = client.post("/scim/v2/Users", json=user_data)
        if response.status_code in (200, 201):
            return response.json()
        else:
            error_context = {
                "status_code": response.status_code,
                "username": username,
                "response": response.text
            }
            raise SCIMError(f"Failed to create user {username}", error_context)
    except SCIMError:
        raise
    except Exception as e:
        error_context = {"username": username, "exception": str(e)}
        raise SCIMError(f"Failed to create user {username}", error_context) from e


def update_user(
    client,
    user_id: str,
    first_name: Optional[str] = None,
    last_name: Optional[str] = None,
    emails: Optional[List[str]] = None
) -> dict:
    """
    Update an existing user's attributes in Grove.

    Only updates attributes that are provided (not None). This ensures we don't
    delete existing values in Grove.

    Args:
        client: HTTP client session (requests.Session)
        user_id: User ID (CUID) to update
        first_name: New given name (optional)
        last_name: New family name (optional)
        emails: New list of email addresses (optional)

    Returns:
        Updated user resource dict

    Raises:
        SCIMError: On API errors

    Example:
        # Update only first name
        user = update_user(client, user_id="user123", first_name="Jane")

        # Update multiple attributes
        user = update_user(
            client,
            user_id="user123",
            first_name="Jane",
            emails=["jane.doe@example.org"]
        )
    """
    operations = []

    # Update name if provided
    if first_name is not None:
        operations.append({
            "op": "replace",
            "path": "name.givenName",
            "value": first_name
        })

    if last_name is not None:
        operations.append({
            "op": "replace",
            "path": "name.familyName",
            "value": last_name
        })

    # Update emails if provided
    if emails is not None:
        emails_data = []
        for idx, email in enumerate(emails):
            emails_data.append({
                "value": email,
                "primary": idx == 0
            })
        operations.append({
            "op": "replace",
            "path": "emails",
            "value": emails_data
        })

    # Only send PATCH if we have operations
    if not operations:
        return get_user(client, user_id)

    patch_data = {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": operations
    }

    try:
        response = client.patch(f"/scim/v2/Users/{user_id}", json=patch_data)
        if response.status_code == 200:
            return response.json()
        else:
            error_context = {
                "status_code": response.status_code,
                "user_id": user_id,
                "operations": operations,
                "response": response.text
            }
            raise SCIMError(f"Failed to update user {user_id}", error_context)
    except SCIMError:
        raise
    except Exception as e:
        error_context = {"user_id": user_id, "exception": str(e)}
        raise SCIMError(f"Failed to update user {user_id}", error_context) from e


def extract_entitlements(user: dict) -> List[str]:
    """
    Extract entitlements from a Grove user object.

    Entitlements in SCIM can be stored as:
    - A simple array of strings: ["entitlement1", "entitlement2"]
    - An array of objects with 'value' field: [{"value": "ent1"}, {"value": "ent2"}]

    This function handles both formats and always returns a simple list of strings.

    Args:
        user: User resource dict from Grove

    Returns:
        List of entitlement strings

    Example:
        user = get_user(client, cuid="user123")
        entitlements = extract_entitlements(user)
        print(f"User has {len(entitlements)} entitlements")
    """
    entitlements = user.get('entitlements', [])
    if not entitlements:
        return []

    # Handle both formats
    result = []
    for ent in entitlements:
        if isinstance(ent, dict):
            # SCIM complex multi-valued attribute: {"value": "...", ...}
            if 'value' in ent:
                result.append(ent['value'])
        elif isinstance(ent, str):
            # Simple string
            result.append(ent)

    return result


def create_http_client(base_url: str, auth_token: str, timeout: int = 5):
    """
    Create an HTTP client session for Grove SCIM API.

    This creates a requests Session configured for Grove SCIM API access,
    similar to create_http_client_session in Perun helpers.

    Args:
        base_url: Base URL of Grove service (e.g., "http://grove-scim:8888")
        auth_token: API key for service account authentication
        timeout: Request timeout in seconds (default: 5)

    Returns:
        Configured requests.Session object

    Example:
        client = create_http_client(
            base_url="http://grove-scim:8888",
            auth_token="your-api-key-here"
        )
        user = get_user(client, cuid="user123")
    """
    import requests
    from functools import partial

    base_url = base_url.rstrip('/')
    session = requests.Session()
    session.base_url = base_url

    # Configure headers - use X-API-Key for service account authentication
    session.headers.update({
        'X-API-Key': auth_token,
        'Content-Type': 'application/scim+json',
        'Accept': 'application/scim+json'
    })

    # Wrap request methods to prepend base_url
    original_request = session.request

    def request_with_base_url(method, url, *args, **kwargs):
        if not url.startswith('http'):
            url = f"{base_url}{url}"
        if 'timeout' not in kwargs:
            kwargs['timeout'] = timeout
        return original_request(method, url, *args, **kwargs)

    session.request = request_with_base_url
    session.get = partial(session.request, 'GET')
    session.post = partial(session.request, 'POST')
    session.patch = partial(session.request, 'PATCH')
    session.delete = partial(session.request, 'DELETE')

    return session
