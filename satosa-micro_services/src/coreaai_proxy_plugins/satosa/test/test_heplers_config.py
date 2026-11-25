from pytest import mark

from coreaai_proxy_plugins.helpers.config import Issuer
from coreaai_proxy_plugins.helpers.config import Requester
from coreaai_proxy_plugins.helpers.config import TableConfig
from coreaai_proxy_plugins.helpers.config import restructure_table_config_to_hierarchical_config
from coreaai_proxy_plugins.helpers.config import get_config_from_hierarchy


class Config(TableConfig):
    value: int


def test_restructure():
    """
    from table/paired configs like the following:

        ```yaml
        config:
          - requester: ""
            issuer: ""
            value: 1
            requester: ""
            issuer: iss_x
            value: 2
          - requester: req_x
            issuer: ""
            value: 3
          - requester: req_x
            issuer: iss_x
            value: 4
          - requester: req_x
            issuer: iss_y
            value: 5
          - requester: req_y
            issuer: iss_x
            value: 6
        ```

    we should get back the following hierarchy:

        ```yaml
        configs:
          "":
            "":
              "value": 1
            "iss_x":
              "value": 2
          "req_x":
            "":
              "value": 3
            "iss_x":
              "value": 4
            "iss_y":
              "value": 5
          "req_y":
            "iss_x":
              "value": 6
        ```
    """

    hconf = restructure_table_config_to_hierarchical_config(table_configs)
    assert hconf == hierarchial_config


@mark.parametrize(
    ("requester", "issuer", "expected_value"),
    (
        ("req_Z", "iss_Z", 1),
        ("req_Z", "iss_x", 2),
        ("req_Z", "iss_y", 1),
        ("req_x", "iss_Z", 3),
        ("req_x", "iss_x", 4),
        ("req_x", "iss_y", 5),
        ("req_y", "iss_Z", 1),
        ("req_y", "iss_x", 6),
        ("req_y", "iss_y", 1),
    ),
)
def test_hierarchy_resolution(requester, issuer, expected_value):
    """
    for a config like the following:

        ```yaml
        config:
          "":
            "":
              value: 1
            iss_x:
              value: 2
          req_x:
            "":
              value: 3
            iss_x:
              value: 4
            iss_y:
              value: 5
          req_y:
            iss_x:
              value: 6
        ```

    we should have the following resolutions:

        | requester   | issuer   | value |
        | ----------- | -------- | ----- |
        | Z           | Z        | 1     |
        | Z           | x        | 2     |
        | Z           | y        | 1     |
        | x           | Z        | 3     |
        | x           | x        | 4     |
        | x           | y        | 5     |
        | y           | Z        | 1     |
        | y           | x        | 6     |
        | y           | y        | 1     |
    """

    conf = get_config_from_hierarchy(hierarchial_config, requester, issuer)
    assert isinstance(conf, Config)
    assert conf.value == expected_value


table_configs = [
    Config(value=1, skip=False, requester=Requester(""), issuer=Issuer("")),
    Config(value=2, skip=False, requester=Requester(""), issuer=Issuer("iss_x")),
    Config(value=3, skip=False, requester=Requester("req_x"), issuer=Issuer("")),
    Config(value=4, skip=False, requester=Requester("req_x"), issuer=Issuer("iss_x")),
    Config(value=5, skip=False, requester=Requester("req_x"), issuer=Issuer("iss_y")),
    Config(value=6, skip=False, requester=Requester("req_y"), issuer=Issuer("iss_x")),
]

hierarchial_config = {
    Requester(""): {
        Issuer(""): table_configs[0],
        Issuer("iss_x"): table_configs[1],
    },
    Requester("req_x"): {
        Issuer(""): table_configs[2],
        Issuer("iss_x"): table_configs[3],
        Issuer("iss_y"): table_configs[4],
    },
    Requester("req_y"): {
        Issuer("iss_x"): table_configs[5],
    },
}
