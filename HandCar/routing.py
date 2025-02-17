# your_project/routing.py
from django.urls import re_path

from  HandCar.App1.consumer import VendorNotificationConsumer

websocket_urlpatterns = [
    re_path(r'ws/notifications/(?P<vendor_id>\d+)/$', VendorNotificationConsumer.as_asgi()),
]
