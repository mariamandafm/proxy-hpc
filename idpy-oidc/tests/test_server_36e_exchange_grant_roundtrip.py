"""
`ExchangeGrant` loses its link to the original session on a dump/load
round-trip.

Root cause: `ExchangeGrant.parameter` declared `"original_session_id"`
but the attribute set by `__init__` is named `original_branch_id`
(`session/grant.py`). `ImpExp.dump` iterates the declared parameters
with `getattr(self, attr, None)`, found no `original_session_id`
attribute, and silently skipped it — the actual `original_branch_id`
value was never serialised, so it was lost on every round-trip (e.g. the
satosa-oidc-frontend SQL session persistence).

The fix aligns the parameter name with the attribute. The field had
never been serialised before, so the rename is backward compatible:
old dumps simply lack the key (loading them keeps the constructor
default, as before), and old code ignores the new key. The regression
test asserts that `original_branch_id` survives a dump/load round-trip;
it failed before the fix and passes after it. A plain guard pins
`exchange_request`, which was declared correctly all along, so any
failure is provably the name mismatch and not the round-trip machinery.
"""

from idpyoidc.message.oauth2 import TokenExchangeRequest
from idpyoidc.server.session.grant import ExchangeGrant

ORIGINAL_BRANCH_ID = "diana;;client_1;;original_grant_id"

EXCHANGE_REQ = TokenExchangeRequest(
    grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
    subject_token="a.subject.token",
    subject_token_type="urn:ietf:params:oauth:token-type:access_token",
    client_id="te_caller",
)


def _roundtrip(grant):
    return ExchangeGrant().load(grant.dump())


class TestExchangeGrantRoundTrip(object):
    def test_exchange_request_survives(self):
        """Guard: `exchange_request` is declared correctly in
        ExchangeGrant.parameter and survives the round-trip — the machinery
        itself works."""
        grant = ExchangeGrant(
            exchange_request=EXCHANGE_REQ,
            original_branch_id=ORIGINAL_BRANCH_ID,
        )
        loaded = _roundtrip(grant)

        assert loaded.exchange_request["client_id"] == "te_caller"

    def test_original_branch_id_survives(self):
        """The link to the original session must survive a dump/load
        round-trip."""
        grant = ExchangeGrant(
            exchange_request=EXCHANGE_REQ,
            original_branch_id=ORIGINAL_BRANCH_ID,
        )
        loaded = _roundtrip(grant)

        assert loaded.original_branch_id == ORIGINAL_BRANCH_ID
