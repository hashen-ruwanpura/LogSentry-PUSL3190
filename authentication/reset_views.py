from django.contrib.auth import views as auth_views, get_user_model
from django.contrib.auth.models import User
from django.contrib.auth.forms import SetPasswordForm
from django.contrib import messages
from django.shortcuts import redirect
import logging
from django.db import transaction, connections
from django.db.models import F
from django.contrib.auth.hashers import make_password
from django.http import HttpResponse
from django.contrib.auth.hashers import check_password

logger = logging.getLogger(__name__)

class CustomPasswordResetConfirmView(auth_views.PasswordResetConfirmView):
    """Custom password reset view that ensures passwords are properly saved in database"""
    
    def form_valid(self, form):
        """Override form_valid to ensure password is saved to database"""
        user = form.user
        username = user.username
        password = form.cleaned_data['new_password1']
        
        logger.info(f"Password reset initiated for user: {username}")
        
        success = False
        error_message = ""
        
        try:
            # Get correct table name from settings
            User = get_user_model()
            db_table = User._meta.db_table  # This should get the correct table name
            logger.info(f"Using database table: {db_table}")
            
            # Method 1: Direct SQL update (most reliable method)
            with connections['default'].cursor() as cursor:
                hashed_password = make_password(password)
                
                # Try table name with and without case sensitivity
                for table_name in [db_table, 'auth_user', 'AuthUser']:
                    try:
                        cursor.execute(
                            f"UPDATE {table_name} SET password = %s WHERE username = %s", 
                            [hashed_password, username]
                        )
                        rows_updated = cursor.rowcount
                        if rows_updated > 0:
                            logger.info(f"SQL update affected {rows_updated} rows in table {table_name} for user: {username}")
                            success = True
                            break
                        logger.warning(f"SQL update to {table_name} affected 0 rows for user: {username}")
                    except Exception as table_error:
                        logger.warning(f"SQL update failed for table {table_name}: {str(table_error)}")
                
                # Force commit
                connections['default'].commit()
                
            # Method 2: Django ORM approach
            if not success:
                try:
                    # Force lookup by username to avoid any cached user issues
                    real_user = User.objects.get(username=username)
                    real_user.set_password(password)
                    real_user.save(update_fields=['password'])
                    logger.info(f"ORM password update completed for: {username}")
                    success = True
                except Exception as orm_error:
                    logger.error(f"ORM update failed: {str(orm_error)}")
                    error_message += f" ORM error: {str(orm_error)}."
            
            # Verify the password was set correctly
            verification_user = None
            try:
                verification_user = User.objects.get(username=username)
                stored_hash = verification_user.password
                logger.info(f"User {username} has password hash in DB: {stored_hash[:20]}... [length: {len(stored_hash)}]")
                
                # Direct hash check
                if check_password(password, stored_hash):
                    logger.info(f"Password verification successful for user: {username}")
                    success = True
                else:
                    logger.error(f"Password verification FAILED for user: {username}")
                    error_message += " Password verification failed."
            except Exception as verify_error:
                logger.error(f"Error during password verification: {str(verify_error)}")
                error_message += f" Verification error: {str(verify_error)}."
            
            # Set success flags in session
            self.request.session['password_reset_username'] = username
            self.request.session['password_reset_success'] = success
            self.request.session['password_hash'] = stored_hash[:20] if verification_user else "Unknown"
            self.request.session.modified = True
            
            if success:
                messages.success(
                    self.request, 
                    f"Password reset successful for {username}. Please login with your new password."
                )
                logger.info(f"Password reset successful for: {username}")
            else:
                messages.error(
                    self.request,
                    f"Password update may have failed. Please try again. {error_message}"
                )
                logger.error(f"Password reset likely failed: {error_message}")
            
            # Continue with standard flow
            return super().form_valid(form)
            
        except Exception as e:
            logger.error(f"Password reset failed: {str(e)}", exc_info=True)
            
            # Add error message
            messages.error(
                self.request,
                f"There was an error resetting your password: {str(e)}. Please try again or contact support."
            )
            
            # Continue with form processing despite error
            return super().form_valid(form)