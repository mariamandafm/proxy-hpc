# Core AAI Community User Identifier Registry

The Core AAI CUID Registry is a microservice that generates and manages persistent CUIDs

## Requirements

- python >= `3.10`
- pip
- make
- docker (if using PostgreSQL)

## Setup

Run `make install_requirements` to install all dev dependencies:

```shell
python3 -m venv venv
cp .env.dst .env
. venv/bin/activate
make install_requirements
```

## Run for development

```
# Use the generated virtual env 
source venv/bin/activate

# Needed if running with postgresql, change in .env file
make db_up

# Apply migrations to database
# based on .env (db_connection_url)
make apply_migrations

# Run the application
make run_local
```

## Run tests

Run `make test`
