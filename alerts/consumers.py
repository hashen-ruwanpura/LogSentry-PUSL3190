import json
import logging
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async

logger = logging.getLogger(__name__)

# --- WEBSOCKET CONSUMERS ---

# Purpose: WebSocket consumer for real-time alerts
# Usage: Establishes persistent connection for pushing real-time notifications
# Related Frontend: JavaScript in base.html and dashboard.html listens for these messages
class AlertConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.user = self.scope["user"]
        
        # Anonymous users can't receive alerts
        if not self.user.is_authenticated:
            await self.close()
            return
            
        # Add to user-specific group
        self.group_name = f"user_{self.user.id}_alerts"
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        
        # Add to severity-based groups if admin
        if self.user.is_staff:
            for severity in ['critical', 'high', 'medium', 'low']:
                group_name = f"severity_{severity}_alerts"
                await self.channel_layer.group_add(group_name, self.channel_name)
        
        # Accept the connection
        await self.accept()
        
        # Send pending alerts on connection (fetch last 5 unread notifications)
        if self.user.is_authenticated:
            pending_alerts = await self.get_pending_alerts()
            if pending_alerts:
                await self.send(text_data=json.dumps({
                    'type': 'pending_alerts',
                    'alerts': pending_alerts
                }))
        
        logger.info(f"WebSocket connected for user {self.user.username}")

    # Add method to fetch pending alerts
    @database_sync_to_async
    def get_pending_alerts(self):
        from alerts.models import AlertNotification
        try:
            # Get last 5 unread notifications
            notifications = AlertNotification.objects.filter(
                user=self.user,
                is_read=False
            ).order_by('-created_at')[:5]
            
            if not notifications:
                return []
                
            # Convert to dict for JSON serialization
            result = []
            for notif in notifications:
                result.append({
                    'id': notif.id,
                    'title': notif.title,
                    'message': notif.message,
                    'severity': notif.severity,
                    'threat_id': notif.threat_id,
                    'source_ip': notif.source_ip,
                    'affected_system': notif.affected_system,
                    'timestamp': notif.created_at.isoformat()
                })
            return result
        except Exception as e:
            logger.error(f"Error fetching pending alerts: {e}")
            return []

    # Purpose: Handle WebSocket disconnection
    # Usage: Automatically called when user navigates away or closes browser
    async def disconnect(self, close_code):
        # Remove from user-specific group
        if hasattr(self, 'group_name'):
            await self.channel_layer.group_discard(self.group_name, self.channel_name)
        
        # Remove from severity groups if admin
        if hasattr(self, 'user') and self.user.is_staff:
            for severity in ['critical', 'high', 'medium', 'low']:
                group_name = f"severity_{severity}_alerts"
                await self.channel_layer.group_discard(group_name, self.channel_name)
                
        logger.info(f"WebSocket disconnected for user {self.user.username if hasattr(self, 'user') else 'unknown'}")

    # Purpose: Handle messages from client to server
    # Usage: Client can send commands like 'ping' or 'mark_read'
    # Related Frontend: JavaScript in notifications.js sends these commands
    async def receive(self, text_data):
        """Handle messages from the client"""
        try:
            data = json.loads(text_data)
            command = data.get('command', '')
            
            if command == 'ping':
                await self.send(text_data=json.dumps({'type': 'pong'}))
            elif command == 'mark_read':
                alert_id = data.get('alert_id')
                if alert_id:
                    await self.mark_alert_read(alert_id)
                    await self.send(text_data=json.dumps({
                        'type': 'alert_updated',
                        'alert_id': alert_id,
                        'status': 'read'
                    }))
        except Exception as e:
            logger.error(f"Error processing WebSocket message: {e}")

    # Enhance the alert_notification method to support more interactive features
    async def alert_notification(self, event):
        """Send alert notification to the client with enhanced data"""
        alert = event['alert']
        
        # Add additional fields based on severity
        if alert.get('severity') == 'critical':
            alert['requires_acknowledgment'] = True
            alert['auto_close'] = False
        elif alert.get('severity') == 'high':
            alert['requires_acknowledgment'] = False
            alert['auto_close'] = False
        else:
            alert['requires_acknowledgment'] = False
            alert['auto_close'] = True
            
        await self.send(text_data=json.dumps({
            'type': 'alert_notification',
            'alert': alert
        }))

    # Purpose: Mark a notification as read from WebSocket
    # Usage: Called when user marks alert as read from notification popup
    @database_sync_to_async
    def mark_alert_read(self, alert_id):
        """Mark an alert as read"""
        from alerts.models import AlertNotification
        try:
            notification = AlertNotification.objects.get(id=alert_id, user=self.user)
            notification.is_read = True
            notification.save()
            return True
        except Exception as e:
            logger.error(f"Error marking alert as read: {e}")
            return False