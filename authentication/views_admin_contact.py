from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.http import JsonResponse
from django.utils import timezone
from django.core.mail import send_mail
from django.contrib import messages
from django.conf import settings
from django.core.paginator import Paginator
from django.db.models import Q

from .models import ContactMessage, AdminReply

import logging
import json

logger = logging.getLogger(__name__)

# Helper function to check if user is admin
def is_superuser(user):
    return user.is_authenticated and user.is_superuser

@login_required
@user_passes_test(is_superuser)
def admin_user_support(request):
    """View to display all contact messages in admin panel"""
    try:
        # Get filter parameters
        status_filter = request.GET.get('status', 'all')
        search_query = request.GET.get('search', '')
        page_number = request.GET.get('page', 1)
        
        # Base queryset
        messages_queryset = ContactMessage.objects.all()
        
        # Apply filters
        if status_filter == 'unread':
            messages_queryset = messages_queryset.filter(is_read=False)
        elif status_filter == 'read':
            messages_queryset = messages_queryset.filter(is_read=True)
        elif status_filter == 'replied':
            messages_queryset = messages_queryset.filter(is_replied=True)
        elif status_filter == 'unreplied':
            messages_queryset = messages_queryset.filter(is_replied=False)
        
        # Apply search if provided
        if search_query:
            messages_queryset = messages_queryset.filter(
                Q(name__icontains=search_query) | 
                Q(email__icontains=search_query) | 
                Q(subject__icontains=search_query) |
                Q(message__icontains=search_query)
            )
        
        # Get counts for sidebar
        total_count = ContactMessage.objects.count()
        unread_count = ContactMessage.objects.filter(is_read=False).count()
        replied_count = ContactMessage.objects.filter(is_replied=True).count()
        
        # Pagination
        paginator = Paginator(messages_queryset.order_by('-created_at'), 10)
        page_obj = paginator.get_page(page_number)
        
        context = {
            'page_obj': page_obj,
            'total_count': total_count,
            'unread_count': unread_count,
            'replied_count': replied_count,
            'status_filter': status_filter,
            'search_query': search_query
        }
        
        # Try multiple template paths to handle different configurations
        template_paths = [
            'admin/adminUserSupport.html',  # Original path
            'frontend/admin/adminUserSupport.html',  # Actual location
        ]
        
        # Add debug logging
        logger.info(f"Attempting to render admin user support page with {len(messages_queryset)} messages")
        
        # Try each template path
        for template_path in template_paths:
            try:
                return render(request, template_path, context)
            except Exception as e:
                logger.warning(f"Failed to render template {template_path}: {str(e)}")
        
        # If we get here, none of the templates worked - show a helpful error
        error_context = {
            'error_message': "Could not find the adminUserSupport.html template",
            'template_paths_tried': template_paths
        }
        return render(request, 'error.html', error_context)
    
    except Exception as e:
        logger.error(f"Error in admin_user_support: {str(e)}")
        context = {
            'error_message': f"An error occurred: {str(e)}",
            'page_obj': None,
            'total_count': 0,
            'unread_count': 0,
            'replied_count': 0,
            'status_filter': 'all',
            'search_query': ''
        }
        return render(request, 'error.html', context)

@login_required
@user_passes_test(is_superuser)
def message_detail(request, message_id):
    """View a specific contact message and its replies"""
    contact_message = get_object_or_404(ContactMessage, id=message_id)
    replies = contact_message.replies.all().order_by('created_at')
    
    # Mark as read if previously unread
    if not contact_message.is_read:
        contact_message.is_read = True
        contact_message.save()
    
    context = {
        'message': contact_message,
        'replies': replies
    }
    
    return render(request, 'admin/message_detail.html', context)

@login_required
@user_passes_test(is_superuser)
def reply_to_message(request, message_id):
    """Submit a reply to a contact message"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Method not allowed'}, status=405)
    
    contact_message = get_object_or_404(ContactMessage, id=message_id)
    
    try:
        data = json.loads(request.body)
        reply_text = data.get('reply_text', '').strip()
        send_email = data.get('send_email', True)  # Get the checkbox state
        
        if not reply_text:
            return JsonResponse({'success': False, 'error': 'Reply text cannot be empty'}, status=400)
        
        # Create the reply
        reply = AdminReply.objects.create(
            contact_message=contact_message,
            admin_user=request.user,
            reply_text=reply_text
        )
        
        # Update contact message status
        contact_message.is_read = True
        contact_message.is_replied = True
        contact_message.save()
        
        # Send email to user with the reply only if requested
        email_sent = False
        if send_email:  # Only send if checkbox is checked
            try:
                send_mail(
                    f'Re: {contact_message.subject}',
                    f"Dear {contact_message.name},\n\n{reply_text}\n\nThank you,\nThe LogSentry Team",
                    settings.DEFAULT_FROM_EMAIL,
                    [contact_message.email],
                    fail_silently=False,
                )
                email_sent = True
            except Exception as e:
                logger.error(f"Failed to send email reply: {str(e)}")
        
        return JsonResponse({
            'success': True, 
            'message': 'Reply sent successfully',
            'email_sent': email_sent,
            'reply': {
                'id': reply.id,
                'admin_user': request.user.username,
                'reply_text': reply.reply_text,
                'created_at': reply.created_at.strftime('%Y-%m-%d %H:%M')
            }
        })
        
    except Exception as e:
        logger.error(f"Error in reply_to_message: {str(e)}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@login_required
@user_passes_test(is_superuser)
def mark_message_read(request, message_id):
    """Mark a message as read"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Method not allowed'}, status=405)
    
    try:
        message = get_object_or_404(ContactMessage, id=message_id)
        message.is_read = True
        message.save()
        
        return JsonResponse({'success': True, 'message': 'Marked as read'})
    except Exception as e:
        logger.error(f"Error marking message as read: {str(e)}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@login_required
@user_passes_test(is_superuser)
def mark_message_unread(request, message_id):
    """Mark a message as unread"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Method not allowed'}, status=405)
    
    try:
        message = get_object_or_404(ContactMessage, id=message_id)
        message.is_read = False
        message.save()
        
        return JsonResponse({'success': True, 'message': 'Marked as unread'})
    except Exception as e:
        logger.error(f"Error marking message as unread: {str(e)}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@login_required
@user_passes_test(is_superuser)
def delete_message(request, message_id):
    """Delete a contact message"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Method not allowed'}, status=405)
    
    try:
        message = get_object_or_404(ContactMessage, id=message_id)
        message.delete()
        
        return JsonResponse({'success': True, 'message': 'Message deleted'})
    except Exception as e:
        logger.error(f"Error deleting message: {str(e)}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@login_required
@user_passes_test(is_superuser)
def contact_message_stats(request):
    """Get statistics about contact messages for the admin dashboard"""
    try:
        # Get total count
        total_count = ContactMessage.objects.count()
        
        # Get unread count
        unread_count = ContactMessage.objects.filter(is_read=False).count()
        
        # Get unreplied count
        unreplied_count = ContactMessage.objects.filter(is_replied=False).count()
        
        # Get recent messages (last 5)
        recent_messages = []
        for msg in ContactMessage.objects.order_by('-created_at')[:5]:
            recent_messages.append({
                'id': msg.id,
                'name': msg.name,
                'subject': msg.subject,
                'created_at': msg.created_at.strftime('%Y-%m-%d %H:%M'),
                'is_read': msg.is_read
            })
        
        return JsonResponse({
            'success': True,
            'total_count': total_count,
            'unread_count': unread_count,
            'unreplied_count': unreplied_count,
            'recent_messages': recent_messages
        })
    except Exception as e:
        logger.error(f"Error getting contact message stats: {str(e)}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@login_required
@user_passes_test(is_superuser)
def message_api_detail(request, message_id):
    """API endpoint to get message details in JSON format"""
    try:
        message = get_object_or_404(ContactMessage, id=message_id)
        
        # Mark as read if previously unread
        if not message.is_read:
            message.is_read = True
            message.save()
        
        # Get all replies - FIXED to use direct query instead of reverse relation
        replies = []
        for reply in AdminReply.objects.filter(contact_message=message).order_by('created_at'):
            replies.append({
                'id': reply.id,
                'reply_text': reply.reply_text,
                'created_at': reply.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'admin_user': reply.admin_user.username if reply.admin_user else 'System'
            })
        
        # Return message details and replies as JSON
        return JsonResponse({
            'success': True,
            'message': {
                'id': message.id,
                'name': message.name,
                'email': message.email,
                'subject': message.subject,
                'message': message.message,
                'created_at': message.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'is_read': message.is_read,
                'is_replied': message.is_replied
            },
            'replies': replies
        })
    except Exception as e:
        logger.error(f"Error fetching message details: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': f"Failed to load message details: {str(e)}"
        }, status=500)