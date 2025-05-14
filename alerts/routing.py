from django.urls import re_path
from . import consumers

websocket_urlpatterns = [
    # Main path for WebSocket connections - make sure to include ws/ prefix
    re_path(r'^ws/alerts/$', consumers.AlertConsumer.as_asgi()),
]