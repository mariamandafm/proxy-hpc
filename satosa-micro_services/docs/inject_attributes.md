# InjectAttributes SATOSA Plugin Guide

## Overview

The `InjectAttributes` plugin for SATOSA is a microservice that allows for
injecting custom attributes into the SAML response based on a variety of
configurable rules. It is highly flexible, supporting different matching
strategies, such as checking for specific attributes, subject IDs, emails, and
entity categories. This is useful in scenarios where identity providers (IdPs)
need to augment attribute data before sending it to service providers (SPs).

This guide explains how to configure and use the `InjectAttributes` plugin in a
service deployment.

## Key Concepts

The `InjectAttributes` plugin works based on a yaml configuration file:

- **Attributes**: The attributes you want to inject into the SAML response.
- **Values**: The values of the attributes to be injected.
- **Rules**: The conditions that must be met before the attributes are injected.
- **Strategy**: Specifies how multiple rules are handled. Options include:
  - `all`: All conditions must be met.
  - `any`: At least one condition must be met.
  - `always`: Always inject the attributes regardless of the rules.

## Configuration Structure

The plugin configuration follows a hierarchical structure:

- **Issuer**: Specifies the entity (the IdP) to which the rules apply.
- **Requester**: Specifies the requesting service provider (SP) for which the
  rules apply.
- **Disabled**: Allows turning off the plugin for specific issuer-requester
  combinations.
- **Attributes**: Defines which attributes should be injected, their values, and
  under what conditions they should be injected.

### Example Configuration

```yaml
module: satosa.micro_services.inject_attributes.InjectAttributes
name: InjectAttributes
config:
  issuer:
    requester:
      # Disables the InjectAttributes for this issuer/requester combination. Default is False.
      disabled: False
      attributes:
        # The name of the attribute to inject
        - attribute: example_attribute
          # The values to inject in the attribute. They can be more than one.
          values: [example_value]
          # If the attribute already has value, should we overwrite them? Default is False.
          overwrite_values: False
          # The strategy to use for the search_for rule. Available options are:
          # - "all" means all rules must match.
          # - "any" means at least one rule must match.
          # - "always" means that the attribute will be injected regardless of the rules.
          strategy: all
          search_for:
            # Define your conditions here.
            attribute: example_search_attribute
            any_authenticating_authority:
              - example_authority_1
              - example_authority_2
```

## `search_for` Options

The `search_for` section in the configuration is used to define conditions under
which the attribute injection will take place. Below are the available
`search_for` options and their explanations.

### Available `search_for` Options

- **attribute**: Checks if a specific attribute exists in the user's internal
  attributes.

  - **Usage**:

    ```yaml
    search_for:
      attribute: some_attribute
    ```

- **any_attributes**: Checks if any of the specified attributes exist in the
  user's internal attributes.

  - **Usage**:

    ```yaml
    search_for:
      any_attributes:
        - some_attribute_a
        - some_attribute_b
    ```

- **all_attributes**: Checks if all of the specified attributes exist in the
  user's internal attributes.

  - **Usage**:

    ```yaml
    search_for:
      all_attributes:
        - some_attribute_a
        - some_attribute_b
    ```

- **any_subject_id**: Checks if any of the specified subject IDs exist in the
  user's internal attributes (e.g., the `subject-id` attribute).

  - **Usage**:

    ```yaml
    search_for:
      any_subject_id:
        - subject_id_1
        - subject_id_2
    ```

- **any_email**: Checks if any of the specified email addresses exist in the
  user's internal attributes.

  - **Usage**:

    ```yaml
    search_for:
      any_email:
        - user@example.com
        - another@example.com
    ```

- **any_eu_login_domain**: Checks if any of the specified EU Login domains exist
  in the user's internal attributes.

  - **Usage**:

    ```yaml
    search_for:
      any_eu_login_domain:
        - domain1.example.com
        - domain2.example.com
    ```

- **any_authenticating_authority**: Checks if any of the specified
  authenticating authorities match the authority of the request.

  - **Usage**:

    ```yaml
    search_for:
      any_authenticating_authority:
        - auth_authority_1
        - auth_authority_2
    ```

- **all_entity_categories**: Checks if all of the specified entity categories
  exist in the metadata for the issuer.

  - **Usage**:

    ```yaml
    search_for:
      all_entity_categories:
        - entity_category_1
        - entity_category_2
    ```

- **all_entity_categories_support**: Checks if all of the specified supported
  entity categories exist in the metadata for the issuer.

  - **Usage**:

    ```yaml
    search_for:
      all_entity_categories_support:
        - supported_entity_category_1
        - supported_entity_category_2
    ```

- **all_assurance_certifications**: Checks if all of the specified assurance
  certifications exist in the metadata for the issuer.

  - **Usage**:

    ```yaml
    search_for:
      all_assurance_certifications:
        - assurance_certification_1
        - assurance_certification_2
    ```

- **any_registration_authorities**: Checks if the issuer is registered with any
  of the specified registration authorities in the metadata.

  - **Usage**:

    ```yaml
    search_for:
      any_registration_authorities:
        - registration_authority_1
        - registration_authority_2
    ```

### `strategy` Options

The `strategy` option defines how to apply the `search_for` rules:

- **all**: All the rules in the `search_for` block must match.
- **any**: At least one rule in the `search_for` block must match.
- **always**: Inject the attributes regardless of the rules.

### Example: Multiple `search_for` Conditions

```yaml
module: satosa.micro_services.inject_attributes.InjectAttributes
name: InjectAttributes
config:
  issuer:
    requester:
      disabled: False
      attributes:
        - attribute: eduPersonScopedAffiliation
          values: [member@example.com]
          overwrite_values: False
          strategy: any
          search_for:
            any_attributes:
              - eduPersonPrincipalName
              - eduPersonUniqueId
            any_email:
              - user1@example.com
              - user2@example.com
            any_eu_login_domain:
              - ecas.europa.eu
```

In this example, the plugin will inject the `eduPersonScopedAffiliation`
attribute with the value `member@example.com` if any of the conditions match
(i.e., if any of the specified attributes or emails exist, or if the domain
matches).
