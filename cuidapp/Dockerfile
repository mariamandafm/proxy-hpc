# requirements/app.txt foi gerado pelo pip-compile sob Python 3.11 (ver o cabeçalho
# do próprio arquivo) — a imagem base acompanha essa versão em vez de assumir outra.
FROM python:3.11-slim

WORKDIR /app

# Copia todo o projeto: requirements/app.txt referencia o próprio repositório
# ("file:.#egg=cuidapp", via setup.py/setup.cfg), então setup.py, setup.cfg, VERSION
# e src/ precisam estar presentes antes do `pip install`.
COPY . .

RUN pip install --no-cache-dir -r requirements/app.txt

# gunicorn.conf.py não define worker_class (o script deploy/app/run.sh que faria isso
# não existe neste checkout) e o worker padrão do gunicorn é WSGI — FastAPI é ASGI,
# o que gera "TypeError: FastAPI.__call__() missing 1 required positional argument:
# 'send'" em toda requisição (confirmado rodando o container). uvicorn 0.49 não traz
# mais o shim uvicorn.workers.UvicornWorker; o pacote uvicorn-worker o substitui —
# mesmo pacote que o scim-api já declara em seu pyproject.toml.
RUN pip install --no-cache-dir uvicorn-worker

RUN chmod +x entrypoint.sh

# gunicorn.conf.py exige APP_INSTALL no ambiente (usado para chdir e para o pidfile).
# PYTHONPATH=/app/src replica o que Makefile:run_local faz manualmente, necessário
# porque main.py/routers.py/settings.py etc. são módulos soltos em src/, não pacotes
# instalados pelo `pip install .` (só db_migration/ e database/ têm __init__.py).
ENV APP_INSTALL=/app \
    PYTHONPATH=/app/src \
    PYTHONUNBUFFERED=1

# Porta fixada em gunicorn.conf.py (bind = ["0.0.0.0:8080"]), não configurável por env.
EXPOSE 8080

ENTRYPOINT ["/app/entrypoint.sh"]
