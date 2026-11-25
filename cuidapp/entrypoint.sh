#!/usr/bin/env bash
set -euo pipefail

# Só espera/valida conectividade quando o backend configurado é Postgres — para
# SQLite (padrão de .env.dst) não há servidor para aguardar.
if [[ "${db_connection_url:-}" == postgresql* ]]; then
  echo "Aguardando o banco de dados ficar disponível..."
  python - <<'PY'
import os
import sys
import time

import psycopg2

url = os.environ["db_connection_url"]
for attempt in range(30):
    try:
        psycopg2.connect(url).close()
        break
    except psycopg2.OperationalError as exc:
        last_error = exc
        time.sleep(1)
else:
    sys.exit(f"Banco de dados inacessível após 30s: {last_error}")
PY
fi

echo "Aplicando migrações (src/db_migration)..."
python src/db_migration/command.py --db-uri "${db_connection_url}" migrate

echo "Iniciando cuidapp..."
# -k precisa ser passado por CLI: gunicorn.conf.py não define worker_class (ver
# comentário no Dockerfile) e o worker padrão (sync/WSGI) não serve uma app ASGI.
exec gunicorn -c gunicorn.conf.py -k uvicorn_worker.UvicornWorker main:app
