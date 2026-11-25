import re

from idpyoidc.server.scopes import Scopes


class GenericScopes(Scopes):
    """
    Match scopes using regex
    """

    def __init__(
        self,
        server_get,
        allowed_scopes=None,
        scopes_to_claims=None,
        allowed_scopes_regex=None,
    ):
        super().__init__(
            server_get, allowed_scopes=allowed_scopes, scopes_to_claims=scopes_to_claims
        )
        self.allowed_scopes_regex = allowed_scopes_regex

    def _get_allowed_scopes(self, client_id=None):
        allowed_scopes = super().get_allowed_scopes(client_id=client_id)
        allowed_scopes_regex = self.allowed_scopes_regex
        if client_id:
            client = self.upstream_get("context").cdb.get(client_id)
            if client is not None:
                if "allowed_scopes_regex" in client:
                    allowed_scopes_regex = client.get("allowed_scopes_regex")
                elif "scopes_to_claims" in client:
                    allowed_scopes_regex = list(client.get("scopes_to_claims").keys())
        return allowed_scopes, allowed_scopes_regex

    def get_allowed_scopes(self, client_id=None):
        allowed_scopes, allowed_scopes_regex = self._get_allowed_scopes(
            client_id=client_id
        )
        return list(set(allowed_scopes + allowed_scopes_regex))

    def filter_scopes(self, scopes, client_id=None):
        ret = []
        allowed_scopes, allowed_scopes_regex = self._get_allowed_scopes(
            client_id=client_id
        )
        for scope in scopes:
            if scope in allowed_scopes:
                ret.append(scope)
            else:
                for reg in allowed_scopes_regex:
                    if re.match(reg, scope):
                        ret.append(scope)

        return ret
