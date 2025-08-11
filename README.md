# OmriSyslog

Python-based syslog server and web dashboard.

## Requirements

- Flask
- Flask-SocketIO
- psutil (for cross-platform system metrics)

## Environment Configuration

The application reads settings from environment variables:

- `SECRET_KEY`: secret key used by Flask for session management. Set this to a
  strong random value in production. If not provided, the application falls back
  to a development key.

