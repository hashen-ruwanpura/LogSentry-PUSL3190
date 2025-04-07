from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.models import User
from django.contrib import messages
from django.http import JsonResponse, HttpResponse
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.template import TemplateDoesNotExist
import json

def is_superuser(user):
    """Helper function to check if a user is a superuser"""
    return user.is_authenticated and user.is_superuser

@login_required
@user_passes_test(is_superuser, login_url='/')
def user_management_view(request):
    """Admin user management page"""
    # Try different template paths until one works
    template_paths = [
        'admin/usermanagement.html',
        'frontend/admin/usermanagement.html'
    ]
    
    for template_path in template_paths:
        try:
            return render(request, template_path)
        except TemplateDoesNotExist:
            continue
    
    # If no template is found, return an error
    return HttpResponse("User management template not found", status=500)


@login_required
@user_passes_test(is_superuser)
def api_user_detail(request, user_id):
    """API endpoint to get details of a specific user"""
    try:
        # Get user or return 404
        user = get_object_or_404(User, id=user_id)
        
        # Format user data for response
        user_data = {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'role': 'admin' if user.is_superuser else 'regular',
            'is_active': user.is_active
        }
        
        return JsonResponse(user_data)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@user_passes_test(is_superuser)
def api_users_list(request):
    """API endpoint to get paginated list of users"""
    # Get query parameters for filtering and pagination
    search_query = request.GET.get('search', '')
    role_filter = request.GET.get('role', '')
    status_filter = request.GET.get('status', '')
    page = request.GET.get('page', 1)
    
    # Start with all users
    users = User.objects.all().order_by('id')
    
    # Apply search filter
    if search_query:
        users = users.filter(username__icontains=search_query) | users.filter(email__icontains=search_query)
    
    # Apply role filter
    if role_filter == 'admin':
        users = users.filter(is_superuser=True)
    elif role_filter == 'regular':
        users = users.filter(is_superuser=False)
    
    # Apply status filter
    if status_filter == 'active':
        users = users.filter(is_active=True)
    elif status_filter == 'inactive':
        users = users.filter(is_active=False)
    
    # Paginate results
    paginator = Paginator(users, 10)  # Show 10 users per page
    
    try:
        users_page = paginator.page(page)
    except PageNotAnInteger:
        users_page = paginator.page(1)
    except EmptyPage:
        users_page = paginator.page(paginator.num_pages)
    
    # Format user data for response
    users_data = []
    for user in users_page:
        users_data.append({
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'role': 'admin' if user.is_superuser else 'regular',
            'last_login': user.last_login.strftime('%Y-%m-%d %H:%M:%S') if user.last_login else 'Never',
            'is_active': user.is_active
        })
    
    # Return JSON response
    return JsonResponse({
        'users': users_data,
        'total_pages': paginator.num_pages,
        'current_page': users_page.number
    })

@login_required
@user_passes_test(is_superuser)
def api_user_create(request):
    """API endpoint to create a new user"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        # Parse JSON data from request body
        data = json.loads(request.body)
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        role = data.get('role')
        is_active = data.get('is_active', True)
        
        # Validate required fields
        if not all([username, email, password]):
            return JsonResponse({'error': 'Missing required fields'}, status=400)
        
        # Check if username already exists
        if User.objects.filter(username=username).exists():
            return JsonResponse({'error': 'Username already exists'}, status=400)
        
        # Create new user
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password
        )
        
        # Set role and active status
        user.is_superuser = (role == 'admin')
        user.is_staff = (role == 'admin')
        user.is_active = is_active
        user.save()
        
        return JsonResponse({'success': True, 'message': 'User created successfully'})
    
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@user_passes_test(is_superuser)
def api_user_update(request, user_id):
    """API endpoint to update an existing user"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        # Get user or return 404
        user = get_object_or_404(User, id=user_id)
        
        # Parse JSON data from request body
        data = json.loads(request.body)
        email = data.get('email')
        role = data.get('role')
        is_active = data.get('is_active')
        password = data.get('password')  # Optional for password reset
        
        # Update user fields if provided
        if email:
            user.email = email
        
        if role is not None:
            user.is_superuser = (role == 'admin')
            user.is_staff = (role == 'admin')
        
        if is_active is not None:
            user.is_active = is_active
        
        # Reset password if provided
        if password:
            user.set_password(password)
        
        user.save()
        
        return JsonResponse({'success': True, 'message': 'User updated successfully'})
    
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@user_passes_test(is_superuser)
def api_user_delete(request, user_id):
    """API endpoint to delete a user"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        # Get user or return 404
        user = get_object_or_404(User, id=user_id)
        
        # Prevent deleting yourself
        if user == request.user:
            return JsonResponse({'error': 'Cannot delete your own account'}, status=400)
        
        # Delete the user
        username = user.username
        user.delete()
        
        return JsonResponse({
            'success': True, 
            'message': f'User {username} deleted successfully'
        })
    
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
