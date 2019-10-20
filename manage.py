#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import sys
from django.core.management.commands.runserver import Command as runserver


def main():
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'THSMap.settings')
    # Override default port and address for 'runserver' command
    runserver.default_port = "8888"
    runserver.default_addr = "127.0.0.1"
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == '__main__':
    main()
