import os

# Logging
accesslog = "-"
errorlog = "-"
loglevel = "debug"

# Process Naming
proc_name = "cuidapp"

# Server Mechanics
chdir = os.environ["APP_INSTALL"]
pidfile = os.path.join(chdir, "cuidapp.pid")

# Server Socket
bind = ["0.0.0.0:8080"]

# Worker Processes
workers = os.getenv("GUNICORN_WORKERS", 2)
# max_requests = 24000
# timeout = 30
