from django.contrib.auth import get_user_model
from .models import Alert, NotificationPreference, EmailNotifier
import random
import logging

logger = logging.getLogger(__name__)
User = get_user_model()

def test_alert_email(email=None, severity="high"):
    """
    Test sending an alert email
    
    Args:
        email: Recipient email address
        severity: Alert severity (critical, high, medium, low)
    """
    try:
        # Create a test alert
        alert_types = [
            "Suspicious Login Attempt", 
            "Brute Force Attack", 
            "SQL Injection Attempt",
            "File Permission Change",
            "Unauthorized Access"
        ]
        
        ip_addresses = [
            "192.168.1.254", "45.33.100.78", "103.74.19.104", 
            "8.8.8.8", "10.0.0.5"
        ]
        
        alert = Alert.objects.create(
            type=random.choice(alert_types),
            source="Test System",
            severity=severity,
            description="This is a test alert to verify the email notification system.",
            ip_address=random.choice(ip_addresses),
            affected_systems="Web Server",
            mitre_tactics="Initial Access, Execution",
            recommendation="This is a test alert. No action is required."
        )
        
        # If no email provided, use all admins
        if not email:
            admin_users = User.objects.filter(is_staff=True)
            
            if not admin_users:
                logger.error("No admin users found to send test email")
                return False
                
            for admin in admin_users:
                if admin.email:
                    # Using the EmailNotifier as implemented in your system
                    EmailNotifier().send_alert(
                        subject=f"[{alert.severity.upper()}] Security Alert: {alert.type}",
                        message=alert.description,
                        severity=alert.severity,
                        recipients=[admin.email],
                        alert_id=alert.id,
                        source_ip=alert.ip_address,
                        affected_system=alert.affected_systems
                    )
                    logger.info(f"Test alert email sent to admin: {admin.email}")
            return True
                
        # Send to the specified email
        result = EmailNotifier().send_alert(
            subject=f"[{alert.severity.upper()}] Security Alert: {alert.type}",
            message=alert.description,
            severity=alert.severity,
            recipients=[email],
            alert_id=alert.id,
            source_ip=alert.ip_address,
            affected_system=alert.affected_systems
        )
        
        if result:
            logger.info(f"Test alert email sent to: {email}")
            return True
        else:
            logger.error(f"Failed to send test alert email")
            return False
        
    except Exception as e:
        logger.error(f"Error creating test alert email: {str(e)}")
        return False

def simple_alert_test(email="itshashenruwanpura@gmail.com", severity="critical"):
    """Simple test that uses Django's email system directly"""
    from django.core.mail import send_mail
    from django.conf import settings
    from .models import Alert
    import random
    import logging
    
    logger = logging.getLogger(__name__)
    
    try:
        # Print current email settings for debugging
        print(f"Using email settings: {settings.EMAIL_BACKEND}")
        print(f"Host: {settings.EMAIL_HOST}, Port: {settings.EMAIL_PORT}")
        print(f"SSL: {settings.EMAIL_USE_SSL}, TLS: {settings.EMAIL_USE_TLS}")
        
        # Create a test alert
        alert_types = ["Suspicious Login Attempt", "Brute Force Attack", "SQL Injection Attempt"]
        
        alert = Alert.objects.create(
            type=random.choice(alert_types),
            source="Test System",
            severity=severity,
            description="This is a test alert to verify the email notification system.",
            ip_address="192.168.1.254",
            affected_systems="Web Server",
            recommendation="This is a test alert. No action is required."
        )
        
        # Send email using Django's built-in send_mail - THIS IS THE KEY CHANGE
        subject = f"[{severity.upper()}] Security Alert: {alert.type}"
        message = f"Test alert detected: {alert.description}\n\nSource IP: {alert.ip_address}\nAffected System: {alert.affected_systems}"
        
        # Use the simple send_mail function that we know works
        result = send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            fail_silently=False
        )
        
        if result > 0:
            logger.info(f"Test alert email sent to {email}")
            return True
        else:
            logger.error("Email was not sent")
            return False
        
    except Exception as e:
        logger.error(f"Error sending test alert: {str(e)}")
        return False

def alert_notifier_test(email="itshashenruwanpura@gmail.com", severity="critical"):
    """Test using the EmailNotifier class directly"""
    from .models import Alert, EmailNotifier
    import random
    import logging
    
    logger = logging.getLogger(__name__)
    
    try:
        # Create a test alert
        alert = Alert.objects.create(
            type="Security Test",
            source="Test System",
            severity=severity,
            description="This is a test alert using EmailNotifier class.",
            ip_address="192.168.1.100",
            affected_systems="Web Server"
        )
        
        # IMPORTANT: Use EmailNotifier as a class method, not an instance
        # This was a key issue in your test_alert_email function!
        result = EmailNotifier.send_alert(
            subject=f"[{severity.upper()}] Test Alert",
            message="This is a test of the EmailNotifier class.",
            severity=severity,
            recipients=[email],
            alert_id=alert.id,
            source_ip=alert.ip_address,
            affected_system=alert.affected_systems
        )
        
        if result:
            logger.info(f"Test alert email sent using EmailNotifier to {email}")
        else:
            logger.error("EmailNotifier failed to send email")
        
        return result
        
    except Exception as e:
        logger.error(f"Error in alert_notifier_test: {str(e)}")
        return False