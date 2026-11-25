#!/bin/sh
# Prepara /etc/satosa a partir de SATOSA/configs (montado em /opt/satosa/configs) e
# inicia o SATOSA com gunicorn.
set -eu

DST=/etc/satosa
KEYS_DIR=/opt/satosa/keys

# 1. Copia a configuração e preenche os "$VAR" (o SATOSA só expande a tag !ENV).
rm -rf "$DST"
mkdir -p "$DST"
cp -r /opt/satosa/configs/. "$DST"/
find "$DST" -type f -name '*.yaml' | while read -r f; do
  envsubst '$SATOSA_BASE_URL $SATOSA_STATE_ENCRYPTION_KEY $OIDC_DB_URI $OIDC_TOKEN_ENCRYPTION_PASSWORD $CUID_ACCESS_TOKEN' \
    < "$f" > "$f.tmp" && mv "$f.tmp" "$f"
done

# 2. Chaves SAML (backend.key/.crt e frontend.key/.crt). Coloque as suas em
#    deploy/satosa/keys/; as que faltarem são geradas (autoassinadas) e ficam lá.
for name in backend frontend; do
  if [ ! -f "$KEYS_DIR/$name.key" ] || [ ! -f "$KEYS_DIR/$name.crt" ]; then
    echo "Gerando par de chaves autoassinado: $name"
    openssl req -x509 -newkey rsa:3072 -nodes -days 3650 -sha256 -subj "/CN=satosa-$name" \
      -keyout "$KEYS_DIR/$name.key" -out "$KEYS_DIR/$name.crt" 2>/dev/null
  fi
  cp "$KEYS_DIR/$name.key" "$KEYS_DIR/$name.crt" "$DST"/
done

# 3. Metadados SAML locais (saml2_frontend.yaml → metadata/perun-sp-metadata.xml) e
#    mapas de atributos.
mkdir -p "$DST/metadata"
cp /opt/satosa/metadata/*.xml "$DST/metadata/" 2>/dev/null || true
if [ ! -f "$DST/metadata/perun-sp-metadata.xml" ]; then
  echo "AVISO: deploy/satosa/metadata/perun-sp-metadata.xml não encontrado;" \
       "usando metadados vazios (o IdP SAML não aceitará nenhum SP)." >&2
  echo '<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"/>' \
    > "$DST/metadata/perun-sp-metadata.xml"
fi
cp -r /opt/satosa/attributemaps "$DST/attributemaps"

# 4. Migrações do banco do frontend OIDC.
satosa-oidc-frontend-db --db-uri "$OIDC_DB_URI" migrate

# Os caminhos relativos dos YAMLs são resolvidos a partir de /etc/satosa.
cd "$DST"
# Um único worker: sem jwks_private_path no frontend OIDC, as chaves de assinatura
# são geradas em memória por processo — workers diferentes assinariam com chaves
# diferentes.
exec gunicorn satosa.wsgi:app --bind 0.0.0.0:8000 --workers 1 \
  --access-logfile - --error-logfile -
