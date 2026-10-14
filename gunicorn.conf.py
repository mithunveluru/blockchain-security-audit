import os

# one worker: capture, detection and the ledger are in-process state, and the ledger takes an exclusive file lock.
# concurrency comes from threads. flask-socketio uses simple-websocket under gthread
bind = os.environ.get("BIND", f"{os.environ.get('HOST', '127.0.0.1')}:{os.environ.get('PORT', '5000')}")
workers = 1
worker_class = "gthread"
threads = int(os.environ.get("GUNICORN_THREADS", "100"))
timeout = 120
graceful_timeout = 10
keepalive = 75
accesslog = "-"
errorlog = "-"
