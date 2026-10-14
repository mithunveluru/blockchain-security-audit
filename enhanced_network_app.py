#!/usr/bin/env python3
"""development entry point. production uses gunicorn with wsgi:app, see the readme"""
import signal
import sys

from blockaudit.config import ConfigError, Settings
from blockaudit.logging_setup import setup


def main():
    log = setup()
    try:
        settings = Settings.from_env()
        from blockaudit.app import create_app
        app, sio, svc = create_app(settings)
    except ConfigError as e:
        print(f"configuration error: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"startup failed: {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    if settings.generated_admin_token:
        print("no BLOCKAUDIT_*_TOKEN set: generated a one-time admin token for this run (sign in with it):\n"
              f"  {settings.generated_admin_token}", file=sys.stderr)
    for w in settings.warnings():
        log.warning(w)
    mode = "simulation (synthetic traffic)" if settings.simulation else f"live capture on {svc.analyzer.interface}"
    print(f"BlockAudit listening on http://{settings.host}:{settings.port}  mode: {mode}", file=sys.stderr)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    try:
        sio.run(app, host=settings.host, port=settings.port, debug=settings.debug, allow_unsafe_werkzeug=not settings.production)
    finally:
        svc.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
