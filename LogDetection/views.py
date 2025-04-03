from django.shortcuts import render

def home(request):
    # Render the home.html template from the Frontend app
    return render(request, 'home.html')



