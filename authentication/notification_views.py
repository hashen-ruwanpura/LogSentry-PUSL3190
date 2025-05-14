

from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
import logging
from django.utils import timezone
from .models import UserDeviceToken
from django.shortcuts import render
from django.core.paginator import Paginator
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.http import require_POST
import json
from alerts.models import AlertNotification

logger = logging.getLogger(__name__)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def register_device(request):
    """Register a device for push notifications"""
    try:
        data = request.data
        device_token = data.get('device_token')
        device_type = data.get('device_type', 'web')
        
        if not device_token:
            return Response({"error": "Device token is required"}, status=status.HTTP_400_BAD_REQUEST)
        
        # Update or create a device token for the user
        token, created = UserDeviceToken.objects.update_or_create(
            user=request.user,
            device_token=device_token,
            defaults={
                'device_type': device_type,
                'is_active': True,
                'last_used_at': timezone.now()
            }
        )
        
        logger.info(f"Device registered for user {request.user.username}: {device_type}")
        
        return Response({
            "success": True,
            "message": "Device registered successfully",
            "created": created
        })
    
    except Exception as e:
        logger.error(f"Error registering device: {str(e)}")
        return Response(
            {"error": "Failed to register device", "details": str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['DELETE', 'POST'])
@permission_classes([IsAuthenticated])
def unregister_device(request):
    """Unregister a device from push notifications"""
    try:
        device_token = None
        
        # Handle both DELETE with query params and POST with body
        if request.method == 'DELETE':
            device_token = request.query_params.get('token')
        else:
            device_token = request.data.get('device_token')
        
        if not device_token:
            return Response({"error": "Device token is required"}, status=status.HTTP_400_BAD_REQUEST)
        
        # Find and update the token
        try:
            token = UserDeviceToken.objects.get(
                user=request.user,
                device_token=device_token
            )
            token.is_active = False
            token.save()
            logger.info(f"Device unregistered for user {request.user.username}")
            
            return Response({
                "success": True,
                "message": "Device unregistered successfully"
            })
            
        except UserDeviceToken.DoesNotExist:
            return Response(
                {"error": "Device token not found for this user"},
                status=status.HTTP_404_NOT_FOUND
            )
    
    except Exception as e:
        logger.error(f"Error unregistering device: {str(e)}")
        return Response(
            {"error": "Failed to unregister device", "details": str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@login_required
def notifications_view(request):
    """View for displaying all notifications"""
    notifications_list = AlertNotification.objects.filter(
        user=request.user
    ).order_by('-created_at')
    
    # Count unread notifications
    unread_count = notifications_list.filter(is_read=False).count()
    
    # Pagination
    paginator = Paginator(notifications_list, 15)  # 15 notifications per page
    page = request.GET.get('page', 1)
    notifications = paginator.get_page(page)
    
    context = {
        'notifications': notifications,
        'unread_count': unread_count
    }
    
    return render(request, 'alerts/notifications.html', context)

@login_required
@require_POST
def mark_notification_read(request, notification_id):
    """Mark a single notification as read"""
    try:
        notification = AlertNotification.objects.get(
            id=notification_id,
            user=request.user
        )
        notification.is_read = True
        notification.save()
        
        return JsonResponse({'success': True})
    except AlertNotification.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Notification not found'}, status=404)

@login_required
@require_POST
def mark_all_read(request):
    """Mark all user's notifications as read"""
    AlertNotification.objects.filter(
        user=request.user,
        is_read=False
    ).update(is_read=True)
    
    return JsonResponse({'success': True})