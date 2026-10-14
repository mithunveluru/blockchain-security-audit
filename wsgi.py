"""gunicorn entry: gunicorn -c gunicorn.conf.py wsgi:app"""
import atexit

from blockaudit.app import create_app
from blockaudit.config import Settings
from blockaudit.logging_setup import setup

setup()
app, socketio, service = create_app(Settings.from_env())
atexit.register(service.close)
