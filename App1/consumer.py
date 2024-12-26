import json
from channels.generic.websocket import AsyncWebsocketConsumer

class VendorNotificationConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        # Vendor-specific group name
        self.vendor_id = self.scope['url_route']['kwargs']['vendor_id']
        self.group_name = f'vendor_{self.vendor_id}'

        # Join vendor group
        await self.channel_layer.group_add(
            self.group_name,
            self.channel_name
        )
        await self.accept()

    async def disconnect(self, close_code):
        # Leave the group
        await self.channel_layer.group_discard(
            self.group_name,
            self.channel_name
        )

    # Receive message from the group
    async def vendor_notification(self, event):
        # Send message to WebSocket
        await self.send(text_data=json.dumps({
            'message': event['message']
        }))
