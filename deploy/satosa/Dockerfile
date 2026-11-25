FROM python:3.11-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends xmlsec1 gettext-base openssl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY --from=pysaml2 . ./pysaml2
RUN pip install --no-cache-dir ./pysaml2

COPY --from=satosa_src setup.py setup.cfg README.md ./SATOSA/
COPY --from=satosa_src src ./SATOSA/src
RUN pip install --no-cache-dir ./SATOSA
COPY --from=idpy_oidc . ./idpy-oidc
RUN rm -rf ./idpy-oidc/build && pip install --no-cache-dir ./idpy-oidc
COPY --from=satosa_oidc_frontend . ./satosa-oidc-frontend
RUN rm -rf ./satosa-oidc-frontend/build \
    && pip install --no-cache-dir --no-deps ./satosa-oidc-frontend \
    && pip install --no-cache-dir \
        "cryptojwt==1.8.4" "cryptography==43.0.3" "pyOpenSSL==24.2.1" \
        alembic "sqlalchemy>=2.0,<2.1" click tabulate cachetools bcrypt psycopg2-binary

COPY --from=satosa_micro_services . ./satosa-micro_services
RUN rm -rf ./satosa-micro_services/build \
    && pip install --no-cache-dir --no-deps ./satosa-micro_services \
    && pip install --no-cache-dir \
        "aarc-entitlement>=1.0.5" ldap3 cryptojwt requests validators toolz \
        requests-toolbelt "PyJWT>=2.0.0,<3.0.0" "typing_extensions>=4.0.0,<5.0.0"

RUN python -c "import os, shutil, saml2.attributemaps as m; shutil.copytree(os.path.dirname(m.__file__), '/opt/satosa/attributemaps', ignore=shutil.ignore_patterns('__pycache__'))"

COPY start.sh /start.sh
RUN chmod +x /start.sh

ENV PYTHONUNBUFFERED=1 \
    SATOSA_CONFIG=/etc/satosa/proxy_conf.yaml

EXPOSE 8000
CMD ["/start.sh"]
