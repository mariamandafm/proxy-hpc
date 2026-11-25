from logging import getLogger as get_logger
from typing import Mapping, Sequence

from coreaai_proxy_plugins.helpers.config import (
    AnyHttpUrl,
    SecretStr,
    TableConfig,
    resolve_config_wrapper,
    restructure_table_config_to_hierarchical_config,
)
from coreaai_proxy_plugins.helpers.grove.scim import (
    SCIMError,
    create_http_client,
    create_user,
    extract_entitlements,
    get_user,
    update_user,
)
from coreaai_proxy_plugins.helpers.logging import ExtraLogger, logging_wrapper
from satosa.context import Context
from satosa.exception import SATOSAError
from satosa.internal import InternalData
from satosa.micro_services.base import ResponseMicroService
from satosa.response import Redirect

logger = ExtraLogger(get_logger(__name__))


DEFAULT_API_TIMEOUT = 5


class Error(SATOSAError):
    def __init__(self, message):
        super().__init__(message)
        self.error_context = message


class ConfigError(Error):
    pass


class Config(TableConfig):
    """Configuration for Grove account management."""

    grove_api_url: AnyHttpUrl
    grove_api_token: SecretStr
    grove_api_timeout: int = DEFAULT_API_TIMEOUT
    error_url: AnyHttpUrl
    error_on_missing_attrs: bool = False
    attr_internal_cuid: str
    attr_internal_first_name: str
    attr_internal_last_name: str
    attr_internal_email: str
    attr_internal_entitlements: str = "entitlements"
    enable_entitlements: bool = True


def _normalize_email_list(emails):
    """Normalize email list to just values for comparison."""
    if not emails:
        return []
    if isinstance(emails, list):
        # Handle both list of strings and list of dicts
        return [e["value"] if isinstance(e, dict) else e for e in emails]
    return [emails]


def _needs_update(existing_user, first_name, last_name, emails):
    """
    Check if user attributes need updating.

    Returns tuple: (needs_update, update_first_name, update_last_name, update_emails)

    Only marks fields for update if SATOSA provides them AND they differ from Grove.
    """
    update_first_name = None
    update_last_name = None
    update_emails = None

    # Check first name
    if first_name is not None:
        existing_first = existing_user.get("name", {}).get("givenName")
        if first_name != existing_first:
            update_first_name = first_name

    # Check last name
    if last_name is not None:
        existing_last = existing_user.get("name", {}).get("familyName")
        if last_name != existing_last:
            update_last_name = last_name

    # Check emails
    if emails:
        existing_emails = _normalize_email_list(existing_user.get("emails", []))
        new_emails = _normalize_email_list(emails)
        # Compare as sets (order doesn't matter for comparison, but we preserve it for update)
        if set(existing_emails) != set(new_emails):
            update_emails = emails

    needs_update = any(
        [
            update_first_name is not None,
            update_last_name is not None,
            update_emails is not None,
        ]
    )

    return needs_update, update_first_name, update_last_name, update_emails


def _process_create_account(
    http_client,
    cuid,
    first_name,
    last_name,
    emails,
    enable_entitlements,
):
    """
    Process account creation or update

    Args:
        http_client: HTTP client session
        cuid: Community Unique Identifier
        first_name: User's given name
        last_name: User's family name
        emails: List of email addresses
        enable_entitlements: Whether to extract entitlements

    Returns:
        dict with 'cuid' and 'entitlements' keys
    """
    # Check if user exists
    user = get_user(http_client, cuid=cuid)

    if user:
        # User exists - check if attributes need updating
        needs_update, update_first, update_last, update_emails = _needs_update(
            user, first_name, last_name, emails
        )

        if needs_update:
            user = update_user(
                http_client,
                user_id=cuid,
                first_name=update_first,
                last_name=update_last,
                emails=update_emails,
            )
    else:
        # Create new user
        user = create_user(
            http_client,
            username=cuid,
            first_name=first_name,
            last_name=last_name,
            emails=emails,
            active=True,
        )

    # Extract entitlements if enabled
    entitlements = []
    if enable_entitlements:
        entitlements = extract_entitlements(user)

    return {
        "cuid": cuid,
        "entitlements": entitlements,
    }


class CreateGroveAccount(ResponseMicroService):
    """
    SATOSA microservice to ensure users exist in Grove with current attributes.

    This microservice:
    1. Checks if a user exists in Grove by CUID
    2. Creates the user if not found
    3. Updates user attributes if they have changed
    4. Extracts entitlements from Grove and adds them to SATOSA attributes

    Updates are only applied for attributes that:
    - Are provided by SATOSA (not None/empty)
    - Have different values than what's stored in Grove

    If SATOSA doesn't provide an attribute, the existing Grove value is preserved.

    Entitlements stored in Grove are extracted and added to the SATOSA attribute
    flow as a list of strings, allowing downstream services to make authorization
    decisions based on user entitlements.

    Configuration is a list of entries resolved per requester and issuer; a
    catch-all entry (empty/omitted ``requester`` and ``issuer``) is required as
    the fallback. Each entry accepts:

    - ``grove_api_url`` - Grove SCIM API base URL
    - ``grove_api_token`` - Grove API bearer token
    - ``grove_api_timeout`` - request timeout in seconds (default 5)
    - ``error_url`` - URL to redirect to on failure
    - ``error_on_missing_attrs`` - if true, redirect to ``error_url`` when the
      required attributes are missing instead of passing through (default false)
    - ``attr_internal_cuid`` - attribute holding the CUID (the Grove username)
    - ``attr_internal_first_name`` / ``attr_internal_last_name`` /
      ``attr_internal_email`` - the user's name and email attributes
    - ``attr_internal_entitlements`` - attribute the extracted entitlements are
      written to (default ``entitlements``)
    - ``enable_entitlements`` - whether to extract entitlements from Grove
      (default true)
    """

    def __init__(self, config: Sequence[Mapping], *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Parse and validate configuration
        try:
            table_configs: Sequence[Config] = [
                Config(
                    grove_api_url=c["grove_api_url"],
                    grove_api_token=c["grove_api_token"],
                    grove_api_timeout=c.get("grove_api_timeout", DEFAULT_API_TIMEOUT),
                    error_url=c["error_url"],
                    error_on_missing_attrs=c["error_on_missing_attrs"],
                    attr_internal_cuid=c["attr_internal_cuid"],
                    attr_internal_first_name=c["attr_internal_first_name"],
                    attr_internal_last_name=c["attr_internal_last_name"],
                    attr_internal_email=c["attr_internal_email"],
                    attr_internal_entitlements=c.get(
                        "attr_internal_entitlements", "entitlements"
                    ),
                    enable_entitlements=c.get("enable_entitlements", True),
                    requester=c.get("requester"),
                    issuer=c.get("issuer"),
                    skip=c.get("skip"),
                )
                for c in config
            ]
        except Exception as e:
            raise ConfigError("Invalid configuration") from e
        if not table_configs:
            raise ConfigError("Invalid configuration")

        # Create hierarchical config structure
        hierarchical_config = restructure_table_config_to_hierarchical_config(
            table_configs
        )
        self.config = hierarchical_config

        logger.info("Initialized Grove account microservice")

    @logging_wrapper(logger)
    @resolve_config_wrapper(logger)
    def process(self, context: Context, data: InternalData, config: Config):
        """
        Process account creation/lookup for authenticated user.

        Args:
            context: SATOSA context
            data: Internal authentication data
            config: Config object (injected by decorator)

        Returns:
            Response to continue SATOSA flow or Redirect on error
        """
        # If config skip flag is set, skip processing
        if not config or config.skip:
            return super().process(context, data)

        # Extract user attributes
        cuid = next(iter(data.attributes.get(config.attr_internal_cuid) or []), None)
        first_name = next(
            iter(data.attributes.get(config.attr_internal_first_name) or []), None
        )
        last_name = next(
            iter(data.attributes.get(config.attr_internal_last_name) or []), None
        )
        emails = data.attributes.get(config.attr_internal_email) or []

        # Validate required attributes
        # if the required attributes for registration are not found then skip processing.
        # the next plugin may raise an error, or redirect to manual registration.
        if not all(attrv for attrv in (cuid, emails)):
            if not config.error_on_missing_attrs:
                return super().process(context, data)

            log_context = {
                "message": "Insufficient attributes",
                "cuid": cuid,
                "emails": emails,
            }
            logger.info(log_context)
            return Redirect(config.error_url)

        # Create HTTP client
        http_client = create_http_client(
            base_url=str(config.grove_api_url),
            auth_token=config.grove_api_token.get_secret_value(),
            timeout=config.grove_api_timeout,
        )

        try:
            # Process account creation/update
            account = _process_create_account(
                http_client,
                cuid,
                first_name,
                last_name,
                emails,
                config.enable_entitlements,
            )
        except SCIMError as e:
            logger.error(e)
            return Redirect(config.error_url)
        except Error as e:
            logger.error(e)
            return Redirect(config.error_url)
        else:
            # Add entitlements to SATOSA attributes if present
            if account["entitlements"]:
                data.attributes[config.attr_internal_entitlements] = account[
                    "entitlements"
                ]
            log_context = {
                "message": "Processed account",
                "account": account,
            }
            logger.info(log_context)

        return super().process(context, data)
