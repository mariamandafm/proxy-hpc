# Regex scopes

The OpenID frontend offers the option for accepting scopes that match to a regex. This
way an infinite number of scopes can be supported. In order to activate it you have to
set `activate_regex_scopes=True` and then define the regex scopes in `allowed_scopes_regex`.
E.g:

```
activate_regex_scopes: True
allowed_scopes_regex:
    - ^custom_scope_.*$
    - ^scopes_[0-9]_scope$
```