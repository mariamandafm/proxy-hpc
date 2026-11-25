import os

from setuptools import find_packages, setup

CURPATH = os.path.dirname(os.path.realpath(__file__))

version_file = os.path.join(CURPATH, "VERSION")
with open(version_file) as f:
    VERSION = f.read().strip()


# Package info
README = open(os.path.join(CURPATH, "README.md")).read()
SHORT_DESCRIPTION = "SATOSA OIDC FRONTEND"

# Package meta
CLASSIFIERS = [
    "Programming Language :: Python :: 3 :: Only",
    "Programming Language :: Python :: 3.6",
    "Programming Language :: Python :: 3.7",
]

# # Package requirements
# requirements_file = os.path.join(CURPATH, "requirements.txt")
# with open(requirements_file) as f:
#     INSTALL_REQUIRES = [x.strip("\n") for x in f.readlines() if x and x[0] != "#"]


setup(
    name="satosa_oidc_frontend",
    version=VERSION,
    license="Apache 2.0",
    url="",
    description=SHORT_DESCRIPTION,
    classifiers=CLASSIFIERS,
    author="Nikos Sklikas, Antonis Angelakis",
    author_email="nsklikas@grnet.gr, angelakis@grnet.gr",
    maintainer="Nikos Sklikas, Antonis Angelakis",
    maintainer_email="nsklikas@grnet.gr, angelakis@grnet.gr",
    packages=find_packages("src/"),
    package_dir={"": "src"},
    include_package_data=True,
    install_requires=[
        "satosa>=8.0.0",
        "idpyoidc @ git+ssh://git@gitlab.geant.org/core-aai-platform/idpy-oidc.git@public#egg=idpyoidc-fork",  # noqa: E501
        "cryptojwt==1.8.4",
        "alembic",
        "sqlalchemy",
        "click",
        "tabulate",
        "cachetools",
        "pydantic",
        "bcrypt",
    ],
    extras_require={
        "mysql": ["PyMySQL"],
        "postgres": ["psycopg2"],
    },
    entry_points={
        "console_scripts": [
            "satosa-oidc-frontend-db=satosa_oidc_frontend.commands.migrate:cli",
            "satosa-oidc-migrate-sessions=satosa_oidc_frontend.commands.migrate_sessions_tokens:migrate",  # noqa: E501
            "satosa-oidc-frontend-clients=satosa_oidc_frontend.commands.clients:cli",
        ]
    },
)
