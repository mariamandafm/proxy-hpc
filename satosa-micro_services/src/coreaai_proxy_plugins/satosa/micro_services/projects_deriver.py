import logging
from typing import Pattern
from re import IGNORECASE as REGEX_FLAG_IGNORECASE
from re import compile as regex_compile
from re import match as regex_match

from satosa.exception import SATOSAError
from satosa.micro_services.base import ResponseMicroService
from satosa.context import Context
from satosa.internal import InternalData

from coreaai_proxy_plugins.helpers.config import TableConfig
from coreaai_proxy_plugins.helpers.config import restructure_table_config_to_hierarchical_config
from coreaai_proxy_plugins.helpers.config import resolve_config_wrapper

from coreaai_proxy_plugins.helpers.logging import ExtraLogger, logging_wrapper

logger = ExtraLogger(logging.getLogger(__name__))

SEPARATOR_URN_TOKEN = ":"
SEPARATOR_GROUP_ROLE = "__role__"
REGEX_GROUP_ROLE = regex_compile(
    f"{SEPARATOR_URN_TOKEN}{SEPARATOR_GROUP_ROLE}({SEPARATOR_URN_TOKEN}|$)"
)


class ProjectsDeriverError(SATOSAError):
    pass


def is_project_woprefix(entitlement: str, ns: str):
    """
    Match value formatted as UUID
    """
    return regex_match(
        rf"{ns}:group:[0-9a-f]{{8}}-[0-9a-f]{{4}}-[0-5][0-9a-f]{{3}}-[089ab][0-9a-f]{{3}}-[0-9a-f]{{12}}",
        entitlement,
        REGEX_FLAG_IGNORECASE,
    )


def is_project_woprefix_with_vo(entitlement: str, ns: str, vo_name: str):
    """
    Match value formatted as UUID
    """
    return regex_match(
        rf"{ns}:group:{vo_name}:[0-9a-f]{{8}}-[0-9a-f]{{4}}-[0-5][0-9a-f]{{3}}-[089ab][0-9a-f]{{3}}-[0-9a-f]{{12}}",
        entitlement,
        REGEX_FLAG_IGNORECASE,
    )


def is_project_pp(entitlement: str, ns: str):
    """
    Match value formatted as "pp" followed by a UUID
    """
    return entitlement.startswith(f"{ns}:group:pp-")


def is_project_pp_with_vo(entitlement: str, ns: str, vo_name: str):
    """
    Match value formatted as "pp" followed by a UUID
    """
    return entitlement.startswith(f"{ns}:group:{vo_name}:pp-")


def is_project_gp(entitlement: str, ns: str):
    """
    Match value formatted as "gp" followed by a UUID
    """
    return entitlement.startswith(f"{ns}:group:gp-")


def is_project_gp_with_vo(entitlement: str, ns: str, vo_name: str):
    """
    Match value formatted as "gp" followed by a UUID
    """
    return entitlement.startswith(f"{ns}:group:{vo_name}:gp-")


def extract_entitlement_role(entitlement: str):
    ent, *r = entitlement.rsplit(":role=", 1)
    role = next(iter(r), None)
    return ent, role


def extract_entitlement_role_alt(entitlement: str):
    ent, *r = entitlement.rsplit(":__role__:", 1)
    role = next(iter(r), None)
    return ent, role


def remove_vo_from_entitlement(entitlement: str):
    ns, groups = entitlement.split(":group:", 1)
    group_vo, *groups_without_vo = groups.split(":", 1)
    groups_new = groups_without_vo[0]
    entitlement_new = f"{ns}:group:{groups_new}"
    return entitlement_new


class Config(TableConfig):
    entitlements_attribute_name: str
    entitlements_ns: str
    entitlements_vo_name: str
    add_entitlements_gp_role_member: bool
    replace_entitlements_values: bool
    derive_role_from_entitlement_groups: bool
    project_attributes_names: list[str]
    project_regexes: list[Pattern]
    replace_project_values: bool


class ProjectsDeriver(ResponseMicroService):
    """
    Derives personal and group projects values

    Example configuration:

    ```yaml
    module: coreaai_proxy_plugins.satosa.micro_services.projects_deriver.ProjectsDeriver
    name: ProjectsDeriver
    config:
      - # The attribute to process its values.
        entitlements_attribute_name: epe
        # The namespace of the entitlements
        entitlements_ns: "urn:example:domain.tld:service"
        # The top-level group/VO that will be removed
        entitlements_vo_name: "foo"
        # Set the entitlement role to "member" for group projects
        add_entitlements_gp_role_member: true
        # Whether the entitlements attribute will be set to the new values
        replace_entitlements_values: true

        # The attribute store the derived values.
        project_attributes_names:
          - eunode_projects
          - groups
        # Set of regexes to match valid projects on input.
        # Make sure to surround the project name.
        project_regexes:
          - "^urn:example:domain.tld:group:(pp-[^:]+).*$"
          - "^urn:example:domain.tld:group:(gp-[^:]+).*$"
        # Whether the derived values sould override the target attribute.
        replace_project_values: true
        # Whether role information should be decoded from entitlements
        derive_role_from_entitlement_groups: true

        requester:
        issuer:
        skip:
    ```
    """

    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config = restructure_table_config_to_hierarchical_config(
            [Config.parse_obj(c) for c in config]
        )

    # Example transformations:
    # - From: urn:example:domain.tld:group:pp-5b4c8c21-8f44-48ec-bfc5-60df831d122f
    #   To:   pp-5b4c8c21-8f44-48ec-bfc5-60df831d122f
    # - From: urn:example:domain.tld:group:gp-0190874a-d1e2-41d8-ace7-61c8038359cc:role=member
    #   To:   gp-0190874a-d1e2-41d8-ace7-61c8038359cc
    # - From: urn:example:domain.tld:group:foo:pp-5b4c8c21-8f44-48ec-bfc5-60df831d122f
    #   To:   pp-5b4c8c21-8f44-48ec-bfc5-60df831d122f
    # - From: urn:example:domain.tld:group:foo:gp-0190874a-d1e2-41d8-ace7-61c8038359cc:role=member
    #   To:   gp-0190874a-d1e2-41d8-ace7-61c8038359cc
    @logging_wrapper(logger)
    @resolve_config_wrapper(logger)
    def process(self, context: Context, data: InternalData, config: Config):
        if not config or config.skip:
            return super().process(context, data)

        entitlements = data.attributes.get(config.entitlements_attribute_name) or []

        # Remove VO from Project entitlements
        entitlements_pp_gp_without_vo = []
        for ent in entitlements:
            # if value is personal project under the VO
            if is_project_pp_with_vo(ent, config.entitlements_ns, config.entitlements_vo_name):
                ent_new = remove_vo_from_entitlement(ent)
                entitlements_pp_gp_without_vo.append(ent_new)
            # if value is group project under the VO
            elif is_project_gp_with_vo(ent, config.entitlements_ns, config.entitlements_vo_name):
                ent_new = remove_vo_from_entitlement(ent)
                entitlements_pp_gp_without_vo.append(ent_new)
            # if value is any other project type under the VO
            elif is_project_woprefix_with_vo(ent, config.entitlements_ns, config.entitlements_vo_name):
                ent_new = remove_vo_from_entitlement(ent)
                entitlements_pp_gp_without_vo.append(ent_new)
            else:
                entitlements_pp_gp_without_vo.append(ent)
        entitlements_new = entitlements_pp_gp_without_vo

        # Restructure role for group entitlements
        if config.derive_role_from_entitlement_groups:
            groups_with_role = []
            entitlements_without_role = []
            for ent in entitlements_new:
                group, *role = REGEX_GROUP_ROLE.split(ent)
                if not role:
                    entitlements_without_role.append(ent)
                elif role[-1]:
                    groups_with_role.append((group, role[-1]))
            _groups_only_with_role = [g for g, e in groups_with_role]
            entitlements_without_role = [
                ent
                for ent in entitlements_without_role
                if ent not in _groups_only_with_role
            ]
            entitlements_with_role = [
                f"{group}:role={role}"
                for group, role in groups_with_role
            ]
            entitlements_new = [*entitlements_without_role, *entitlements_with_role]

            # Remove role information from Personal Project entitlements
            entitlements_with_pp_no_role = []
            for ent in entitlements_new:
                if is_project_pp(ent, config.entitlements_ns):
                    group, role = extract_entitlement_role(ent)
                    if group not in entitlements_with_pp_no_role:
                        entitlements_with_pp_no_role.append(group)
                else:
                    entitlements_with_pp_no_role.append(ent)
            entitlements_new = entitlements_with_pp_no_role

        # Add role "member" for Group Project entitlements with missing role information
        if config.add_entitlements_gp_role_member:
            entitlements_gp_with_role = []
            for ent in entitlements_new:
                if not is_project_gp(ent, config.entitlements_ns):
                    entitlements_gp_with_role.append(ent)
                    continue

                ent_wo_role, role = extract_entitlement_role(ent)
                if role:
                    entitlements_gp_with_role.append(ent)
                    continue

                ent_new = f"{ent}:role=member"
                entitlements_gp_with_role.append(ent_new)
            entitlements_new = entitlements_gp_with_role

        # Derive Projects from enttilements
        derived_values = []
        for v in entitlements_new:
            for r in config.project_regexes:
                match = r.match(v)
                if match:
                    project = match.groups()[0]
                    if project not in derived_values:
                        derived_values.append(project)
                    break

        # Update the derived attribute
        if derived_values:
            for attr in config.project_attributes_names:
                if config.replace_project_values:
                    data.attributes[attr] = derived_values[:]
                else:
                    data.attributes[attr] = [
                        *data.attributes[attr],
                        *derived_values[:],
                    ]

        # Update entitlements attribute
        if config.replace_project_values and entitlements_new:
            data.attributes[config.entitlements_attribute_name] = entitlements_new

        log_report = {
            "messsage": "Derived project values",
            "derived_values": derived_values,
            "derived_entitlements": entitlements_new,
        }
        logger.info(log_report)

        return super().process(context, data)
