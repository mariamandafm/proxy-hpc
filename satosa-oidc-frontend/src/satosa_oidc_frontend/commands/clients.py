import os

import click
from sqlalchemy import create_engine
from tabulate import tabulate

from satosa_oidc_frontend import utils


def format_redirect_uri(uri):
    if isinstance(uri, str):
        return uri
    elif isinstance(uri, list):
        return uri[0]
    else:
        raise ValueError(f"Unexpected redirect_uri: {uri}")


def format_redirect_uris(uris):
    return [format_redirect_uri(uri) for uri in uris]


@click.group()
@click.option(
    "--db-uri",
    type=str,
    help="A db_uri to use in order to connect to the database, defaults to env "
    "var 'SATOSA_OIDC_FRONTEND_DB_URI'",
    default=lambda: os.environ.get("SATOSA_OIDC_FRONTEND_DB_URI", ""),
)
@click.pass_context
def cli(ctx, db_uri):
    ctx.obj = dict(engine=create_engine(db_uri))


@cli.command(name="get")
@click.pass_context
@click.argument("client_id")
def get_client(ctx, client_id):
    """Get a client's info"""
    engine = ctx.obj["engine"]
    cid, info = utils.get_client(engine, client_id)
    if not cid:
        print(f"No client with client_id '{client_id}'")
        return

    if "redirect_uris" in info:
        info["redirect_uris"] = format_redirect_uris(info["redirect_uris"])
    print(tabulate([["Client ID", cid]] + list(info.items())))


@cli.command(name="create")
@click.pass_context
@click.argument("client_id")
@click.argument("client_secret")
@click.option(
    "--redirect-uris",
    type=str,
    help="One or more comma separated redirect_uris",
)
@click.option(
    "--response-types",
    type=str,
    help="One or more comma separated response types",
)
@click.option(
    "--grant-types-supported",
    type=str,
    help="One or more comma separated grant types "
    "e.g. --grant-types-supported authorization_code,refresh_token",
)
@click.option(
    "--allowed-scopes",
    type=str,
    help="One or more comma separated allowed scopes "
    "e.g. --allowed-scopes openid,profile",
)
@click.option(
    "--claims-always-access-token",
    type=str,
    help="One or more comma separated claims to be added to the access token "
    "e.g. --claims-always-access-token first_name,birth_date",
)
@click.option(
    "--claims-always-id-token",
    type=str,
    help="One or more comma separated claims to be added to the id token "
    "e.g. --claims-always-id-token first_name,birth_date",
)
@click.option(
    "--claims-always-userinfo",
    type=str,
    help="One or more comma separated claims to be added to the userinfo token "
    "e.g. --claims-always-userinfo first_name,birth_date",
)
@click.option(
    "--revoke-refresh-on-issue",
    is_flag=True,
    help="Revoke refresh tokens after they have been used",
)
@click.option(
    "--pkce-essential",
    is_flag=True,
    help="Make use of PKCE is mandatory",
)
@click.option(
    "--claims-by-scope-access-token",
    type=bool,
    default=False,
    help="Add claims by scope to the access token, "
    "e.g. --claims-by-scope-access-token true",
)
@click.option(
    "--claims-by-scope-id-token",
    type=bool,
    default=False,
    help="Add claims by scope to the id token," "e.g. --claims-by-scope-id-token true",
)
@click.option(
    "--claims-by-scope-userinfo",
    type=bool,
    default=True,
    help="Add claims by scope to the userinfo," "e.g. --claims-by-scope-userinfo false",
)
@click.option(
    "--client-param",
    "-p",
    help=("Set another client param e.g. -p post_logout_redirect_uri=http://some/path"),
    multiple=True,
)
def create_client(
    ctx,
    client_id,
    client_secret,
    redirect_uris=None,
    claims_always_access_token=None,
    claims_always_id_token=None,
    claims_always_userinfo=None,
    claims_by_scope_access_token=False,
    claims_by_scope_id_token=False,
    claims_by_scope_userinfo=False,
    allowed_scopes=None,
    client_param=(),
    grant_types_supported=None,
    pkce_essential=False,
    response_types=None,
    revoke_refresh_on_issue=False,
):
    """Create a client"""
    engine = ctx.obj["engine"]
    client_info = {
        "client_secret": client_secret,
    }

    if redirect_uris:
        client_info["redirect_uris"] = redirect_uris.split(",")
    if allowed_scopes:
        client_info["allowed_scopes"] = allowed_scopes.split(",")
    if grant_types_supported:
        client_info["grant_types_supported"] = grant_types_supported.split(",")
    if response_types:
        client_info["response_types"] = response_types.split(",")
    client_info["pkce_essential"] = pkce_essential
    client_info["revoke_refresh_on_issue"] = revoke_refresh_on_issue
    if claims_always_access_token:
        client_info["claims_always_access_token"]: claims_always_access_token.split(",")
    if claims_always_id_token:
        client_info["claims_always_id_token"]: claims_always_id_token.split(",")
    if claims_always_userinfo:
        client_info["claims_always_userinfo"]: claims_always_userinfo.split(",")
    if claims_by_scope_access_token:
        client_info["claims_by_scope_access_token"] = claims_by_scope_access_token
    if claims_by_scope_id_token:
        client_info["claims_by_scope_id_token"] = claims_by_scope_id_token
    if claims_by_scope_userinfo:
        client_info["claims_by_scope_userinfo"] = claims_by_scope_userinfo
    for k, v in map(lambda x: x.split("=", 1), client_param):
        if k in client_info:
            raise click.ClickException(
                "--client-param {k}={v} conflicts with another param."
            )
        client_info[k] = v

    try:
        client_id, client_info = utils.create_client(engine, client_id, **client_info)
    except ValueError:
        raise click.ClickException(
            f"Client with client_id '{client_id}' already exists, use "
            "the `modify` command instead"
        )
    if "redirect_uris" in client_info:
        client_info["redirect_uris"] = format_redirect_uris(
            client_info["redirect_uris"]
        )
    print(tabulate([["Client ID", client_id]] + list(client_info.items())))


@cli.command(name="modify")
@click.pass_context
@click.argument("client_id")
@click.option(
    "--add-redirect-uri",
    type=str,
    help="Add a redirect_uri",
    multiple=True,
)
@click.option(
    "--add-response-type",
    type=str,
    help="Add a response type",
    multiple=True,
)
@click.option(
    "--add-grant-type-supported",
    type=str,
    help="Add a supported grant types "
    "e.g. --add-grant-type-supported authorization_code",
    multiple=True,
)
@click.option(
    "--add-allowed-scope",
    type=str,
    help="Add an allowed scope e.g. --add-allowed-scope profile",
    multiple=True,
)
@click.option(
    "--add-claim-always-access-token",
    type=str,
    help="Add a claim to be added to the access token "
    "e.g. --add-claim-always-access-token first_name "
    "--add-claim-always-access-token last_name",
    multiple=True,
)
@click.option(
    "--add-claim-always-id-token",
    type=str,
    help="Add a claim to be added to the id token "
    "e.g. --add-claim-always-id-token first_name "
    "--add-claim-always-id-token last_name",
)
@click.option(
    "--add-claim-always-userinfo",
    type=str,
    help="Add a claim to be added to the userinfo token "
    "e.g. --add-claim-always-userinfo first_name "
    "--add-claim-always-userinfo last_name",
    multiple=True,
)
@click.option(
    "--add-client-param",
    help=(
        "Add a client param "
        "e.g. --add-client-param post_logout_redirect_uri=http://some/path"
    ),
    multiple=True,
)
@click.option(
    "--redirect-uris",
    type=str,
    help="One or more comma separated redirect_uris",
)
@click.option(
    "--response-types",
    type=str,
    help="One or more comma separated response types",
)
@click.option(
    "--grant-types-supported",
    type=str,
    help="One or more comma separated grant types "
    "e.g. --grant-types-supported authorization_code,refresh_token",
)
@click.option(
    "--allowed-scopes",
    type=str,
    help="One or more comma separated allowed scopes "
    "e.g. --allowed-scopes openid,profile",
)
@click.option(
    "--claims-always-access-token",
    type=str,
    help="One or more comma separated claims to be added to the access token "
    "e.g. --claims-always-access-token first_name,birth_date",
)
@click.option(
    "--claims-always-id-token",
    type=str,
    help="One or more comma separated claims to be added to the userinfo token "
    "e.g. --claims-always-userinfo first_name,birth_date",
)
@click.option(
    "--claims-always-userinfo",
    type=str,
    help="One or more comma separated claims to be added to the userinfo token "
    "e.g. --claims-always-userinfo first_name,birth_date",
)
@click.option(
    "--claims-by-scope-access-token",
    type=bool,
    help="Add claims by scope to the access token, "
    "e.g. --claims-by-scope-access-token true",
)
@click.option(
    "--claims-by-scope-id-token",
    type=bool,
    help="Add claims by scope to the id token," "e.g. --claims-by-scope-id-token true",
)
@click.option(
    "--claims-by-scope-userinfo",
    type=bool,
    help="Add claims by scope to the userinfo, "
    "e.g. --add-claims-by-scope-userinfo false",
)
@click.option(
    "--revoke-refresh-on-issue",
    type=bool,
    help="Revoke refresh tokens after they have been used",
)
@click.option(
    "--pkce-essential",
    type=bool,
    help="Make use of PKCE is mandatory",
)
@click.option(
    "--client-secret",
    type=str,
    help="Change the client's secret",
)
@click.option(
    "--remove-redirect-uri",
    type=str,
    help="Remove a redirect_uri",
    multiple=True,
)
@click.option(
    "--remove-response-type",
    type=str,
    help="Remove a response type",
    multiple=True,
)
@click.option(
    "--remove-grant-type-supported",
    type=str,
    help="Remove a supported grant types "
    "e.g. --remove-grant-type-supported authorization_code",
    multiple=True,
)
@click.option(
    "--remove-allowed-scope",
    type=str,
    help="Remove an allowed scope e.g. --remove-allowed-scope profile",
    multiple=True,
)
@click.option(
    "--remove-claim-always-access-token",
    type=str,
    help="Remove a claim to be added to the access token "
    "e.g. --remove-claim-always-access-token first_name "
    "--remove-claim-always-access-token last_name",
    multiple=True,
)
@click.option(
    "--remove-claim-always-id-token",
    type=str,
    help="Remove a claim to be added to the id token "
    "e.g. --remove-claim-always-id-token first_name "
    "--remove-claim-always-id-token last_name",
)
@click.option(
    "--remove-claim-always-userinfo",
    type=str,
    help="Remove a claim to be added to the userinfo token "
    "e.g. --remove-claim-always-userinfo first_name "
    "--remove-claim-always-userinfo last_name",
    multiple=True,
)
@click.option(
    "--remove-client-param",
    help=(
        "Remove a client param " "e.g. --remove-client-param post_logout_redirect_uri"
    ),
    multiple=True,
)
def modify_client(
    ctx,
    client_id,
    **kwargs,
):
    """Modify an existing client"""
    engine = ctx.obj["engine"]
    args = {}
    add_allowed_scope = kwargs.pop("add_allowed_scope")
    if add_allowed_scope:
        args["add_allowed_scopes"] = add_allowed_scope
    add_claim_always_access_token = kwargs.pop("add_claim_always_access_token")
    if add_claim_always_access_token:
        args["add_claims_always_access_token"] = add_claim_always_access_token
    add_claim_always_id_token = kwargs.pop("add_claim_always_id_token")
    if add_claim_always_id_token:
        args["add_claims_always_id_token"] = add_claim_always_id_token
    add_claim_always_userinfo = kwargs.pop("add_claim_always_userinfo")
    if add_claim_always_userinfo:
        args["add_claims_always_userinfo"] = add_claim_always_userinfo
    add_grant_type_supported = kwargs.pop("add_grant_type_supported")
    if add_grant_type_supported:
        args["add_grant_types_supported"] = add_grant_type_supported
    add_redirect_uri = kwargs.pop("add_redirect_uri")
    if add_redirect_uri:
        args["add_redirect_uris"] = add_redirect_uri
    add_response_type = kwargs.pop("add_response_type")
    if add_response_type:
        args["add_response_types"] = add_response_type

    remove_allowed_scope = kwargs.pop("remove_allowed_scope")
    if remove_allowed_scope:
        args["remove_allowed_scopes"] = remove_allowed_scope
    remove_claim_always_access_token = kwargs.pop("remove_claim_always_access_token")
    if remove_claim_always_access_token:
        args["remove_claims_always_access_token"] = remove_claim_always_access_token
    remove_claim_always_id_token = kwargs.pop("remove_claim_always_id_token")
    if remove_claim_always_id_token:
        args["remove_claims_always_id_token"] = remove_claim_always_id_token
    remove_claim_always_userinfo = kwargs.pop("remove_claim_always_userinfo")
    if remove_claim_always_userinfo:
        args["remove_claims_always_userinfo"] = remove_claim_always_userinfo
    remove_grant_type_supported = kwargs.pop("remove_grant_type_supported")
    if remove_grant_type_supported:
        args["remove_grant_types_supported"] = remove_grant_type_supported
    remove_redirect_uri = kwargs.pop("remove_redirect_uri")
    if remove_redirect_uri:
        args["remove_redirect_uris"] = remove_redirect_uri
    remove_response_type = kwargs.pop("remove_response_type")
    if remove_response_type:
        args["remove_response_types"] = remove_response_type

    add_client_param = kwargs.pop("add_client_param")
    if add_client_param:
        args["add_extra"] = {
            k: v for (k, v) in map(lambda x: x.split("=", 1), add_client_param)
        }
    remove_client_param = kwargs.pop("remove_client_param")
    if remove_client_param:
        args["remove_extra"] = remove_client_param
    for p in [
        "redirect_uris",
        "allowed_scopes",
        "grant_types_supported",
        "response_types",
        "claims_always_access_token",
        "claims_always_id_token",
        "claims_always_userinfo",
    ]:
        if kwargs[p] is not None:
            args[p] = kwargs.pop(p).split(",")
    args.update(kwargs)
    try:
        client_id, client_info = utils.modify_client(engine, client_id, **args)
    except ValueError:
        raise click.ClickException(
            f"Client with client_id '{client_id}' does not exist, use "
            "the `create` command instead"
        )
    if "redirect_uris" in client_info:
        client_info["redirect_uris"] = format_redirect_uris(
            client_info["redirect_uris"]
        )
    print(tabulate([["Client ID", client_id]] + list(client_info.items())))


@cli.command(name="delete")
@click.pass_context
@click.argument("client_id")
def delete_client(ctx, client_id):
    """Delete a client"""
    engine = ctx.obj["engine"]
    res = utils.delete_client(engine, client_id)
    if res == 0:
        print(f"No client with client_id {client_id}")
        return
    print(f"Successfully deleted client with client_id {client_id}")


@cli.command(name="list")
@click.pass_context
def list_clients(ctx):
    """List all clients"""
    engine = ctx.obj["engine"]
    all_clients = utils.get_all_clients(engine)
    clients = []
    for client in all_clients:
        info = client.client_info
        clients.append(
            [
                client.client_id,
                info.get("client_secret"),
                format_redirect_uris(info.get("redirect_uris")),
            ]
        )

    print(tabulate(clients, headers=["Client ID", "Client Secret", "Redirect URIS"]))
