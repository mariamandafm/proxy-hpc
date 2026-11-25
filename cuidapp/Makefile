SHELL := bash
.ONESHELL:
include .env

.PHONY: install_requirements
## Install development requirements
install_requirements:
	python3 -m pip install virtualenv pip-tools
	python3 -m venv venv
	source venv/bin/activate && pip install -r requirements/test.txt

.PHONY: update_app_requirements
## Update requirements file for application
update_app_requirements:
	pip-compile requirements/app.in

.PHONY: update_dev_requirements
## Update requirements file for development
update_dev_requirements:
	pip-compile requirements/test.in

.PHONY: apply_migrations
## Apply DB migrations
apply_migrations:
	python src/db_migration/command.py --db-uri ${db_connection_url} migrate

.PHONY: run_local
## Run cuidapp locally
run_local:
	export APP_INSTALL="$(shell pwd)" && \
	export PYTHONPATH=src/ && \
		./deploy/app/run.sh main:app

.PHONY: db_up
## Run database as a docker container
db_up:
	docker-compose -p cuidapp up postgresql -d

.PHONY: db_down
## Stop database container
db_down:
	docker-compose -p cuidapp stop postgresql

.PHONY: test
## Run tests
test:
	rm test.db || true
	source venv/bin/activate && \
		export PYTHONPATH=src/ \
		export db_connection_url="sqlite:///test.db" && \
		export enable_util_endpoints="true" && \
		python -m src.db_migration.command --db-uri sqlite:///test.db migrate && \
		pytest -s --cov-report term-missing --cov=src/ tests/

.PHONY: format
## Run formatting tools: black, ruff, isort
format:
	@black src/ tests/
	@ruff src/ tests/ --fix
	@isort src/ tests/ --profile=black

.DEFAULT_GOAL := show_help
# See <https://gist.github.com/klmr/575726c7e05d8780505a> for explanation.
.PHONY: show_help
show_help:
	@echo "$$(tput bold)Available rules:$$(tput sgr0)";echo;sed -ne"/^## /{h;s/.*//;:d" -e"H;n;s/^## //;td" -e"s/:.*//;G;s/\\n## /---/;s/\\n/ /g;p;}" ${MAKEFILE_LIST}|LC_ALL='C' sort -f|awk -F --- -v n=$$(tput cols) -v i=30 -v a="$$(tput setaf 6)" -v z="$$(tput sgr0)" '{printf"%s%*s%s ",a,-i,$$1,z;m=split($$2,w," ");l=n-i;for(j=1;j<=m;j++){l-=length(w[j])+1;if(l<= 0){l=n-i-length(w[j])-1;printf"\n%*s ",-i," ";}printf"%s ",w[j];}printf"\n";}'|more $(shell test $(shell uname) == Darwin && echo '-Xr')
