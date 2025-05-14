import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.contrib.auth import get_user_model
from .models import AlertNotification

User = get_user_model()

class AlertConsumer(AsyncWebsocketConsumer):
    """
    WebSocket consumer for handling real-time alert notifications.
    This class handles WebSocket connections with proper lifecycle methods.
    """
    
    async def connect(self):
        """Handle new WebSocket connection"""
        try:
            # Get the user from the scope
            self.user = self.scope["user"]
            
            # Reject connection if user is not authenticated
            if not self.user.is_authenticated:
                print(f"WebSocket connection rejected: User not authenticated")
                await self.close()
                return
            
            print(f"WebSocket connect attempt for user {self.user.username}")
            
            # Add to user-specific notification group
            self.user_group_name = f"user_{self.user.id}_alerts"
            await self.channel_layer.group_add(
                self.user_group_name,
                self.channel_name
            )
            
            # Add to admin notifications group if user is admin/staff
            if self.user.is_staff or self.user.is_superuser:
                self.admin_group_name = "admin_alerts"
                await self.channel_layer.group_add(
                    self.admin_group_name,
                    self.channel_name
                )
                
            # Accept the connection
            await self.accept()
            print(f"WebSocket connection accepted for user {self.user.username}")
            
            # Send connection confirmation
            await self.send(text_data=json.dumps({
                'type': 'connection_established',
                'message': 'Connected to notification server'
            }))
            
            # Send recent notifications on connect
            recent_notifications = await self.get_recent_notifications()
            if recent_notifications:
                await self.send(text_data=json.dumps({
                    'type': 'recent_notifications',
                    'notifications': recent_notifications
                }))
                
        except Exception as e:
            print(f"Error in WebSocket connect: {str(e)}")
            # If connection is still open, close it
            if hasattr(self, 'channel_name'):
                await self.close()

    async def disconnect(self, close_code):
        """Handle WebSocket disconnection"""
        try:
            # Leave user-specific group
            if hasattr(self, 'user_group_name'):
                await self.channel_layer.group_discard(
                    self.user_group_name,
                    self.channel_name
                )
                
            # Leave admin group if part of it
            if hasattr(self, 'admin_group_name'):
                await self.channel_layer.group_discard(
                    self.admin_group_name,
                    self.channel_name
                )
                
            print(f"WebSocket disconnected for user {self.user.username if hasattr(self, 'user') else 'unknown'}, code: {close_code}")
        except Exception as e:
            print(f"Error in WebSocket disconnect: {str(e)}")

    async def receive(self, text_data):
        """Handle incoming messages from WebSocket"""
        try:
            data = json.loads(text_data)
            command = data.get('command')
            
            # Handle ping command
            if command == 'ping':
                await self.send(text_data=json.dumps({
                    'type': 'pong',
                    'timestamp': data.get('timestamp')
                }))
                
            # You can add handlers for other commands here
                
        except Exception as e:
            print(f"Error in WebSocket receive: {str(e)}")

    # Handler for alert_notification type messages from channel layer
    async def alert_notification(self, event):
        """Handle alert notifications sent via channel layer"""
        try:
            # Forward the notification to the WebSocket
            await self.send(text_data=json.dumps({
                'type': 'notification',
                'notification': event['alert']
            }))
        except Exception as e:
            print(f"Error sending notification to WebSocket: {str(e)}")

    @database_sync_to_async
    def get_recent_notifications(self):
        """Get recent unread notifications for the user"""
        try:
            # Get last 5 unread notifications for the user
            notifications = AlertNotification.objects.filter(
                user=self.user,
                read=False
            ).order_by('-created_at')[:5]
            
            # Format for JSON response
            return [
                {
                    'id': notification.id,
                    'title': notification.title,
                    'message': notification.message,
                    'severity': notification.severity,
                    'created_at': notification.created_at.isoformat(),
                    'threat_id': notification.threat_id
                }
                for notification in notifications
            ]
        except Exception as e:
            print(f"Error getting recent notifications: {str(e)}")
            return []