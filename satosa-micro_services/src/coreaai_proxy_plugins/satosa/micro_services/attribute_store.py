"""
SATOSA microservice that uses an identifier asserted by
the home organization SAML IdP as a key to search an LDAP
directory or API for a record and then consume attributes from
the record and assert them to the receiving SP.
"""

from functools import partial
from logging import getLogger as get_logger
from copy import deepcopy as _clone
from requests_toolbelt.sessions import BaseUrlSession as create_http_client_session

from toolz.itertoolz import unique as uniquify_seq
import ldap3
from ldap3.core.exceptions import LDAPException

import requests

from coreaai_proxy_plugins.helpers.perun.rpc.user import get_attrs, get_user
from satosa.internal import InternalData
from satosa.context import Context
from satosa.response import Redirect
from satosa.exception import SATOSAError
from satosa.micro_services.base import ResponseMicroService

from coreaai_proxy_plugins.helpers.logging import ExtraLogger
from coreaai_proxy_plugins.helpers.logging import logging_wrapper
from coreaai_proxy_plugins.helpers.perun.rpc.errors import Error as PerunError


init_logger = get_logger(__name__)
logger = ExtraLogger(init_logger)


class Error(SATOSAError):
    """
    Attribute store error
    """

    pass


class AttributeStore(ResponseMicroService):
    """
    Use identifier provided by the backend authentication service
    to lookup a person record in LDAP or API and obtain attributes
    to assert about the user to the frontend receiving service.
    """

    config_defaults: dict = {
        "look_up_strategy": "ldap",
        "bind_dn": None,
        "bind_password": None,
        "clear_input_attributes": False,
        "clear_input_attributes_except": [],
        "ignore": False,
        "attr_internal_cuid_preset": None,
        "attr_internal_cuid": None,
        "ldap_identifier_attribute": None,
        "ldap_url": None,
        "on_ldap_search_result_empty": None,
        "ordered_identifier_candidates": None,
        "pool_size": 10,
        "pool_keepalive": 10,
        "search_base": None,
        "search_return_attributes": None,
        "eppn_attr": None,
        "eppn_scope": None,
        "continue_url_state_key": "",
        "api_url": None,
        "api_auth_user": None,
        "api_auth_password": None,
        "api_timeout": None,
        "ext_source_name": None,
        "ldap_search_membership": False,
        "look_up_strategy": None,
        "error_url": None,
    }

    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if "default" in config and "" in config:
            msg = """Use either 'default' or "" in config but not both"""
            init_logger.error(msg)
            raise Error(msg)

        if "" in config:
            config["default"] = config.pop("")

        if "default" not in config:
            msg = "No default configuration is present"
            init_logger.error(msg)
            raise Error(msg)

        self.config = {}

        # Process the default configuration first then any per-SP overrides.
        sp_list = ["default"]
        sp_list.extend([key for key in config.keys() if key != "default"])

        ldap_connections = {}
        http_clients = {}

        for sp in sp_list:
            if not isinstance(config[sp], dict):
                msg = "Configuration value for {} must be a dictionary"
                init_logger.error(msg)
                raise Error(msg)

            # Initialize configuration using module defaults then update
            # with configuration defaults and then per-SP overrides.
            sp_config = _clone(AttributeStore.config_defaults)
            if "default" in self.config:
                sp_config.update(self.config["default"])
            sp_config.update(config[sp])

            look_up_strategy = sp_config["look_up_strategy"]

            if look_up_strategy == "ldap":
                self._init_ldap_connection(sp_config, ldap_connections, sp)
            elif look_up_strategy == "api":
                if not sp_config.get("ext_source_name"):
                    msg = "ext_source_name' is mandatory to configure in the case of look_up_strategy: 'api'."
                    init_logger.error(msg)
                    raise Error(msg)
                self._init_http_client(sp_config, http_clients, sp)
            else:
                msg = "look_up_strategy' could only have one of the following values: 'api', 'ldap'."
                init_logger.error(msg)
                raise Error(msg)

            self.config[sp] = sp_config

    def _init_ldap_connection(self, sp_config, connections, sp):
        # Tuple to index existing LDAP connections so they can be
        # re-used if there are no changes in parameters.
        connection_params = (
            sp_config["bind_dn"],
            sp_config["bind_password"],
            sp_config["ldap_url"],
            sp_config["search_base"],
        )

        if connection_params in connections:
            sp_config["connection"] = connections[connection_params]
            msg = f"Reusing LDAP connection for SP {sp}"
            init_logger.debug(msg)
        else:
            try:
                connection = self._ldap_connection_factory(sp_config)
                connections[connection_params] = connection
                sp_config["connection"] = connection
                msg = f"Created new LDAP connection for SP {sp}"
                init_logger.debug(msg)
            except Error:
                # It is acceptable to not have a default LDAP connection
                # but all SP overrides must have a connection, either
                # inherited from the default or directly configured.
                if sp != "default":
                    init_logger.error(
                        f"LDAP connection cannot be initialized for SP {sp}"
                    )

    def _init_http_client(self, sp_config, http_clients, sp):
        # Tuple to index existing HTTP clients so they can be
        # re-used if there are no changes in parameters.
        http_client_params = (
            sp_config["api_url"],
            sp_config["api_auth_user"],
            sp_config["api_auth_password"],
            sp_config["api_timeout"],
        )

        if http_client_params in http_clients:
            sp_config["http_client"] = http_clients[http_client_params]
            msg = f"Reusing HTTP client for SP {sp}"
            init_logger.debug(msg)
        else:
            http_client = create_http_client_session(base_url=sp_config["api_url"])
            http_client.request = partial(http_client.request, timeout=sp_config["api_timeout"])
            http_client.auth = (sp_config["api_auth_user"], sp_config["api_auth_password"])

            http_clients[http_client_params] = http_client
            sp_config["http_client"] = http_client
            msg = f"Created new HTTP client for SP {sp}"
            init_logger.debug(msg)

    def _construct_query_value(self, candidate, internal_data):
        """
        Collect the list of identifier values for a candidate, or None.

        Argument 'candidate' is a dictionary with one required key:

        key              required   value
        ---------------  --------   ---------------------------------
        attribute_names  Y          list of identifier names

        Argument 'internal_data' is the object passed into the microservice
        method process().

        The values asserted for each configured identifier name are collected
        into a list (used to build the LDAP search filter). If any configured
        identifier name has no asserted value the candidate is skipped and None
        is returned.
        """

        attributes = internal_data.attributes

        # Get the values configured list of identifier names for this candidate
        # and substitute None if there are no values for a configured
        # identifier.
        values = []
        for identifier_name in candidate["attribute_names"]:
            v = attributes.get(identifier_name, None)
            if isinstance(v, list):
                values.extend(v)
            else:
                values.append(v)

        # If no value was asserted by the IdP for one of the configured list
        # of identifier names for this candidate then go onto the next
        # candidate.
        if None in values:
            logger.warning("Candidate is missing value so skipping")
            return None

        logger.debug(f"Constructed filter with values {','.join(values)}")

        return values

    def _filter_config(self, config, fields=None):
        """
        Filter sensitive details like passwords from a configuration
        dictionary.
        """
        filter_fields = fields or ["bind_password", "api_auth_password", "connection"]
        return {
            key: "<hidden>" if key in filter_fields else config[key]
            for key in config
        }

    def _ldap_connection_factory(self, config):
        """
        Use the input configuration to instantiate and return
        a ldap3 Connection object.
        """
        ldap_url = config["ldap_url"]
        bind_dn = config["bind_dn"]
        bind_password = config["bind_password"]

        if not ldap_url:
            raise Error("ldap_url is not configured")
        if not bind_dn:
            raise Error("bind_dn is not configured")
        if not bind_password:
            raise Error("bind_password is not configured")

        pool_size = config["pool_size"]
        pool_keepalive = config["pool_keepalive"]

        server = ldap3.Server(config["ldap_url"])

        log_data = {
            "msg": "Creating a new LDAP connection",
            "ldap_url": ldap_url,
            "ldap_bind_dn": bind_dn,
            "ldap_pool_size": pool_size,
            "ldap_pool_keep_alive": pool_keepalive,
        }

        init_logger.debug(log_data)

        try:
            connection = ldap3.Connection(
                server,
                bind_dn,
                bind_password,
                auto_bind=True,
                client_strategy=ldap3.REUSABLE,
                pool_size=pool_size,
                pool_keepalive=pool_keepalive,
            )
        except LDAPException as e:
            msg = f"Caught exception when connecting to LDAP server: {e}"
            init_logger.error(msg)
            raise Error(msg) from e

        init_logger.debug("Successfully connected to LDAP server")

        return connection

    def _populate_attributes(self, config, record, internal_data):
        """
        Use a record found in LDAP or API response to populate attributes.
        """
        search_return_attributes = config["search_return_attributes"]
        for attr_name, internal_attr_names in search_return_attributes.items():
            record_attr_vals = record["attributes"].get(attr_name, [])
            if not record_attr_vals:
                msg = (
                    f"Not setting internal attributes {internal_attr_names} "
                    f"because no values were returned: {record_attr_vals}"
                )
                logger.debug(msg)
                continue

            if type(record_attr_vals) is not list:
                record_attr_vals = [record_attr_vals]
            if type(internal_attr_names) is not list:
                internal_attr_names = [internal_attr_names]

            for int_attr_name in internal_attr_names:
                # TODO: Needs refactoring
                # add scope to eppn if it does not have one
                if int_attr_name == config["eppn_attr"] and config["eppn_scope"]:
                    record_attr_vals = [
                        f"{attr_val}@{config['eppn_scope']}"
                        for attr_val in record_attr_vals
                        if "@" not in attr_val
                    ]

                int_attr_name_values = list(
                    uniquify_seq(
                        [
                            *(internal_data.attributes.get(int_attr_name) or []),
                            *record_attr_vals,
                        ]
                    )
                )
                internal_data.attributes[int_attr_name] = int_attr_name_values
                logger.debug(
                    f"Setting internal attribute {int_attr_name} "
                    f"with values: {int_attr_name_values}"
                )

    @logging_wrapper(logger)
    def process(self, context: Context, internal_data: InternalData):
        """
        Default interface for microservices. Process the input internal_data
        for the input context.
        """

        # Find the entityID for the SP that initiated the flow.
        try:
            sp_entity_id = context.state.state_dict["SATOSA_BASE"]["requester"]
        except KeyError:
            logger.error("Unable to determine the entityID for the SP requester")
            return super().process(context, internal_data)

        logger.debug(f"entityID for the SP requester is {sp_entity_id}")

        # Get the configuration for the SP.
        if sp_entity_id in self.config.keys():
            logger.debug(f"Found configuration for SP: {sp_entity_id}")
            config = self.config[sp_entity_id]
        else:
            config = self.config["default"]

        logger.debug(f"Initialized with configuration: {self._filter_config(config)}")
        # Ignore this SP entirely if so configured.
        if config["ignore"]:
            logger.info(f"Ignoring SP {sp_entity_id}")
            return super().process(context, internal_data)

        lookup_strategy = config["look_up_strategy"]

        attr_internal_cuid = config.get("attr_internal_cuid")
        attr_internal_cuid_preset = config.get("attr_internal_cuid_preset")
        cuid = internal_data.attributes.get(attr_internal_cuid_preset)
        if attr_internal_cuid_preset and cuid:
            internal_data.attributes[attr_internal_cuid] = cuid
            # In the case of LDAP as the lookup strategy, if CUID is set, skip processing
            if lookup_strategy == "ldap":
                log_ctx = {
                    "message": "CUID already set; setting attribute and skipping",
                    "attr_internal_cuid_preset": attr_internal_cuid_preset,
                    "attr_internal_cuid": attr_internal_cuid,
                    "cuid": cuid,
                }
                logger.info(log_ctx)
                return super().process(context, internal_data)

        if lookup_strategy == "ldap":
            record = self._search_via_ldap(config, internal_data)
        else:
            cuid = internal_data.attributes.get(attr_internal_cuid)
            # CUID is mandatory in the case if look_up strategy is API. In future, we should also be able to retrieve
            # the attributes against IUID.
            if not cuid:
                logger.info("CUID is not available; unable to proceed")
                return super().process(context, internal_data)
            record = self._search_via_api(config, cuid)

        continue_url_state_key = config.get("continue_url_state_key")
        if not record:
            logger.info("User not found")
            on_ldap_search_result_empty = config["on_ldap_search_result_empty"]
            if on_ldap_search_result_empty:
                continue_url = context.state.get(continue_url_state_key)
                _params = (
                    {"targetnew": continue_url}
                    if continue_url_state_key and continue_url
                    else {}
                )

                _req = requests.models.PreparedRequest()
                _req.prepare_url(on_ldap_search_result_empty, _params)
                logger.info("Registration flow activated.")
                return Redirect(_req.url)

            # No record and no registration redirect: pass through unchanged.
            return super().process(context, internal_data)

        if isinstance(record, list) and len(record) > 1:
            redirect_url = config.get("error_url")
            # This should not happen; the redirect_url should always be set
            if not redirect_url:
                # Abandon processing!
                return super().process(context, internal_data)
            return Redirect(redirect_url)

        # Before using a found record, if any, to populate attributes
        # clear any attributes incoming to this microservice if so configured.
        if config["clear_input_attributes"]:
            logger.debug(
                f"Clearing values for input attributes except "
                f"{config['clear_input_attributes_except']}"
            )
            internal_data.attributes = self._clear_attributes(
                internal_data.attributes, config["clear_input_attributes_except"]
            )

        # Use a found record, if any, to populate attributes and input for NameID
        if record.get("dn"):
            logger.debug(f"LDAP record with DN {record['dn']} has attributes {record['attributes']}")
        else:
            logger.debug(f"Record from the API call has attributes {record['attributes']}")

        # Populate attributes as configured.
        self._populate_attributes(config, record, internal_data)
        logger.info(f"User found: {internal_data.attributes.get('subject-id')}")

        return super().process(context, internal_data)

    def _search_via_ldap(self, config, internal_data):
        # The list of values for the LDAP search filters that will be tried in
        # order to find the LDAP directory record for the user.
        filter_values = []

        # Loop over the configured list of identifiers from the IdP to
        # consider and find asserted values to construct the ordered list of
        # values for the LDAP search filters.
        for candidate in config["ordered_identifier_candidates"]:
            values = self._construct_query_value(candidate, internal_data)

            # If we have constructed a non empty value then add it as the next
            # filter value to use when searching for the user record.
            if values:
                filter_values.extend(values)
                logger.debug(
                    f"Added search filter values {','.join(values)} "
                    f"to list of search filters"
                )

        # Initialize an empty LDAP record. The first LDAP record found using
        # the ordered list of search filter values will be the record used.
        record = []

        try:
            connection = config["connection"]

            search_filter = ""

            for filter_val in filter_values:
                search_filter += f"({config['ldap_identifier_attribute']}={filter_val})"

            if search_filter:
                search_filter = f"(|{search_filter})"

                if config.get("ldap_search_membership"):
                    search_filter = f"(&(groupNames={config['account_registry_vo']}){search_filter})"
                logger.debug(f"Constructed search filter {search_filter}")

                logger.info("Querying the LDAP server")
                message_id = connection.search(
                    config["search_base"],
                    search_filter,
                    attributes=config["search_return_attributes"].keys(),
                )

                responses = connection.get_response(message_id)[0]
                logger.info("Finished querying the LDAP server")
                logger.debug(f"LDAP server returned {len(responses)} records")

                # for now consider only the first record found (if any)
                if len(responses) == 1:
                    record = responses[0]
                elif len(responses) > 1:
                    logger.error(
                        f"LDAP server returned {len(responses)} "
                        f"records using search filter value {search_filter}"
                    )
                    record = responses
        except LDAPException as err:
            logger.error(f"Caught LDAP exception: {err}")
            raise Exception(err) from err
        except Error as err:
            logger.error(f"Caught Attribute Store exception: {err}")
            raise Exception(err) from err
        except Exception as err:
            logger.error(f"Caught unhandled exception: {err}")
            raise Exception(err) from err

        return record

    def _search_via_api(self, config, cuid):
        try:
            http_client = config["http_client"]
            if isinstance(cuid, list):
                cuid = cuid[0]
            logger.debug(f"Calling the usersManager/getUserByExtSourceNameAndExtLogin API with extLogin: {cuid}")
            response = get_user(http_client, config["ext_source_name"], cuid)
            logger.info("Finished calling the usersManager/getUserByExtSourceNameAndExtLogin API")
            user_id = response.get("id")
            logger.debug(f"Successfully retrieved the user_id: {user_id}")
            logger.debug(f"Calling the attributesManager/getAttributes API with identifier value: {user_id}")
            attribute_names = list(config["search_return_attributes"].keys())
            response = get_attrs(http_client, user_id, attribute_names)
            logger.info("Finished calling the attributesManager/getAttributes API")
            logger.debug(f"Response from attributesManager/getAttributes API call: {response}")
            attributes = dict()
            for attribute in response:
                attribute_name = attribute.get("namespace") + ":" + attribute.get("friendlyName")
                attributes[attribute_name] = attribute.get("value")
            return {"attributes": attributes}
        except PerunError as err:
            logger.error(f"Caught Perun RPC API Error: {err}")
            raise Exception(err) from err
        except Exception as err:
            logger.error(f"Caught unhandled exception: {err}")
            raise Exception(err) from err

    def _clear_attributes(self, attributes, exclusions=None):
        exclusions = exclusions or []
        for key in list(attributes.keys()):
            if key not in exclusions:
                attributes.pop(key, None)
        return attributes
