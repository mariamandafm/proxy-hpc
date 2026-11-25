# User Attribute Processor

## Usage guide

### Components

 - Attributes - Represents information stored about a user.  
   e.g. `user_email_address` is satosa's `internal_data.attributes.mail` field.  
   ```yaml
   # This is exactly the same as user_email_address
   attribute_path:
     name: custom_path
     path:
       - attributes
       - mail
   ```
 - Predicates - The conditions to check on when to apply specific `Actions`. Will output either `True` or `False`  
   e.g. `is_contained_in_static_list`: Is the current user's email (`user_email_address`) contained in a whitelist
   ```yaml
   name: is_contained_in_static_list
   source_attribute: 
     name: user_email_address
   # Or the following: This will behave exactly the same
   # name: custom_path
   # path:
   #   - attributes
   #   - mail
   static_list:
     - email.address1@test.com
     - email.address2@test.com
     - email.address3@test.com
   ```
 - Actions - What action should be done after evaluating the predicates  
   e.g. `redirect`: Will halt the authentication process to redirect the user to a specified URL
   ```yaml
   name: redirect
   redirect_url: https://www.google.com
   ```

### Microservice Configuration
These three components are combined to create flexible rules expressed in YAML.  
Take note that these rules may be specified for specific issuer/requester pairs.

The microservice configuration is composed of `Rules` which are itself composed of the components above.

Example: All users with emails NOT in the specified list must be redirected to www.google.com
```yaml
user_attribute_processor_config:
  - rules: # Notice we can specify more than one rule here
      - name: Redirect if user email is not in list # A description of what is happening
        predicate: # What should be checked?
          condition:
            name: is_contained_in_static_list
            source_attribute:
              attribute_path:
                name: user_email_address
            static_list:
              - ric.sapasap@geant.org
              - mae.sapasap@geant.org
        failure_actions:  # list of actions to do if a user fails the predicate
          - name: redirect
            redirect_url: https://www.google.com/
        success_actions: [] # list of actions to do if a user succeeds the predicate
                            # This is empty since we won't do anything for this specific scenario
```

### List of available components
These are used as the `name` attribute of the component

#### Attributes
1. `user_email_address`   
   The email address attribute of the authenticating user (`attributes.mail`)

2. `custom_path`  
   Specify a path starting from Satosa's `internal_data` variable.  
   `path` is a list of strings to navigate `internal_data`:  
   ```yaml
   # This is exactly the same as user_email_address
   attribute_path:
     name: custom_path
     path:
       - attributes
       - mail
   ```

#### Predicates
1. `is_contained_in_static_list` - Checks if the attribute is contained in `static_list`
   ```yaml
   name: is_contained_in_static_list
   source_attribute: 
     name: user_email_address
   ignore_case: False # default
   static_list:
     - email.address1@test.com
     - email.address2@test.com
     - email.address3@test.com
   ```
2. `regex_match` - Check if an attribute matches a `regex_pattern`
   ```yaml
   name: regex_match
   source_attribute: 
     name: user_email_address
   ignore_case: True              # Default is False
   regex_pattern: "^.*@test.com"  # match any email with a "test.com" domain
   ```
3. `always_true` - Always returns true
   ```yaml
   name: always_true
   ```
4. `always_false` - Always returns false
   ```yaml
   name: always_false
   ```
5. `not` - Negate a predicate
   ```yaml
   # This will always return false
   name: not
   condition: 
     name: always_true
   ```
6. `or` - Performs pairwise or operations on a list of conditions
   ```yaml
   # Returns true (true || false)
   name: or
   conditions:
    - name: always_true
    - name: always_false
   ```
7. `and` - Performs pairwise and operations on a list of conditions
   ```yaml
   # Returns true (true && true)
   name: and
   conditions:
    - name: always_true
    - name: always_true
   ```

#### Actions
1. `redirect` - Redirect to a URL
   ```yaml
   name: redirect
   redirect_url: https://www.google.com/
   ```
2. `add_literal_attribute` - Add a literal value as an attribute
   ```yaml
   # sets internal_data.attributes.some.custom.path.key to LITERAL_VALUE
   name: add_literal_attribute
   attribute: 
     name: custom_path
     path:
       - attributes
       - some
       - custom
       - path
       - key
   value: LITERAL_VALUE
   create_parent_paths: True # Create the path to the attribute, if it doesn't exist, default True
   override_existing_value: True # override the existing value if it exists, default True
   ```
3. `next_microservice` - Finish processing and go to next microservice
   ```yaml
   name: next_microservice
   ```