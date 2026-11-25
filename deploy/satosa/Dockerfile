# Imagem do SATOSA com o frontend OIDC e os plugins do Core AAI.
#
# Os contextos adicionais (satosa_src, idpy_oidc, satosa_oidc_frontend,
# satosa_micro_services) são declarados no docker-compose.yaml.
FROM python:3.11-slim

# xmlsec1: assinatura/validação SAML (pysaml2)
# gettext-base: envsubst, usado pelo start.sh para preencher os "$VAR" dos YAMLs
# openssl: gera as chaves SAML que não forem fornecidas
RUN apt-get update \
    && apt-get install -y --no-install-recommends xmlsec1 gettext-base openssl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Fork GÉANT do pysaml2 (./pysaml2), instalado antes do SATOSA para satisfazer o
# "pysaml2>=6.5.1" dele em vez da versão do PyPI.
COPY --from=pysaml2 . ./pysaml2
RUN pip install --no-cache-dir ./pysaml2

# SATOSA (./SATOSA)
COPY --from=satosa_src setup.py setup.cfg README.md ./SATOSA/
COPY --from=satosa_src src ./SATOSA/src
RUN pip install --no-cache-dir ./SATOSA

# Fork GÉANT do idpy-oidc (./idpy-oidc), exigido pelo satosa-oidc-frontend (o
# setup.py dele aponta para git+ssh://gitlab.geant.org, inacessível no build).
COPY --from=idpy_oidc . ./idpy-oidc
RUN rm -rf ./idpy-oidc/build && pip install --no-cache-dir ./idpy-oidc

# Frontend OIDC do Core AAI. --no-deps pelo mesmo motivo acima; as demais
# dependências vão à parte (psycopg2-binary: o banco do frontend é PostgreSQL).
# cryptography/pyOpenSSL fixados nas versões da imagem de referência
# (core-aai-platform/SATOSA): o cryptojwt==1.8.4 exigido pelo frontend usa as curvas
# binárias (ec.SECT571R1...), removidas nas versões mais novas do cryptography.
COPY --from=satosa_oidc_frontend . ./satosa-oidc-frontend
RUN rm -rf ./satosa-oidc-frontend/build \
    && pip install --no-cache-dir --no-deps ./satosa-oidc-frontend \
    && pip install --no-cache-dir \
        "cryptojwt==1.8.4" "cryptography==43.0.3" "pyOpenSSL==24.2.1" \
        alembic "sqlalchemy>=2.0,<2.1" click tabulate cachetools bcrypt psycopg2-binary

# Plugins do Core AAI (coreaai_proxy_plugins). --no-deps: o pacote declara
# pydantic<2, incompatível com o resto da imagem; as dependências vão à parte.
COPY --from=satosa_micro_services . ./satosa-micro_services
RUN rm -rf ./satosa-micro_services/build \
    && pip install --no-cache-dir --no-deps ./satosa-micro_services \
    && pip install --no-cache-dir \
        "aarc-entitlement>=1.0.5" ldap3 cryptojwt requests validators toolz \
        requests-toolbelt "PyJWT>=2.0.0,<3.0.0" "typing_extensions>=4.0.0,<5.0.0"

# saml2_frontend.yaml usa attribute_map_dir: attributemaps, e o SATOSA não traz
# essa pasta: usa os mapas padrão do pysaml2.
RUN python -c "import os, shutil, saml2.attributemaps as m; shutil.copytree(os.path.dirname(m.__file__), '/opt/satosa/attributemaps', ignore=shutil.ignore_patterns('__pycache__'))"

COPY start.sh /start.sh
RUN chmod +x /start.sh

ENV PYTHONUNBUFFERED=1 \
    SATOSA_CONFIG=/etc/satosa/proxy_conf.yaml

EXPOSE 8000
CMD ["/start.sh"]
