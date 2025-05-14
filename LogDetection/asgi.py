"""
ASGI config for LogDetection project.
"""

import os
import django
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
from channels.security.websocket import AllowedHostsOriginValidator
import alerts.routing

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'LogDetection.settings')
django.setup()

# Get the Django ASGI application
django_asgi_app = get_asgi_application()

application = ProtocolTypeRouter({
    "http": django_asgi_app,
    "websocket": AllowedHostsOriginValidator(
        AuthMiddlewareStack(
            URLRouter(
                alerts.routing.websocket_urlpatterns
            )
        )
    ),
})
