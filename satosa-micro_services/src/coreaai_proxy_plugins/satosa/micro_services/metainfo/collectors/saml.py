def collect_entity_metadata(mdstore, entity_id, metadata_field_names):
    metadata = {
        "display_name": get_display_name(mdstore, entity_id),
        "privacy_statement": get_privacy_statement(mdstore, entity_id),
        "contacts": get_contacts(mdstore, entity_id),
        "entity_categories": get_entity_categories(mdstore, entity_id),
        "supported_entity_categories": get_supported_entity_categories(mdstore, entity_id),
        "assurance_certifications": get_assurance_certifications(mdstore, entity_id),
        "registration_info": get_registration_info(mdstore, entity_id),
        "issuer_shibmd_scopes": get_issuer_shibmd_scopes(mdstore, entity_id),
    }

    if metadata_field_names:
        return {field: metadata[field] for field in metadata_field_names if field in metadata}
    return metadata


def get_display_name(mdstore, entity_id):
    display_name = (
        next(mdstore.mdui_uiinfo_display_name(entity_id, langpref="en"), None)
        or mdstore.name(entity_id)
    )
    return display_name


def get_privacy_statement(mdstore, entity_id):
    privacy_statement = next(
        mdstore.mdui_uiinfo_privacy_statement_url(entity_id, langpref="en"), None
    )
    return privacy_statement


def get_contacts(mdstore, entity_id):
    contacts = list(mdstore.contact_person_data(entity_id))
    return contacts


def get_entity_categories(mdstore, entity_id):
    entity_categories = mdstore.entity_categories(entity_id)
    return entity_categories


def get_supported_entity_categories(mdstore, entity_id):
    supported_entity_categories = mdstore.supported_entity_categories(entity_id)
    return supported_entity_categories


def get_assurance_certifications(mdstore, entity_id):
    assurance_certifications = list(mdstore.assurance_certifications(entity_id))
    return assurance_certifications


def get_registration_info(mdstore, entity_id):
    registration_info = mdstore.registration_info(entity_id) or {}
    return registration_info


def get_issuer_shibmd_scopes(mdstore, entity_id):
    scopes = list(mdstore.shibmd_scopes(entity_id, typ="idpsso_descriptor"))
    return scopes
