from django import forms
from .models import LogSource

class LogSourceForm(forms.ModelForm):
    class Meta:
        model = LogSource
        fields = ['name', 'source_type', 'file_path', 'enabled']
        widgets = {
            'file_path': forms.TextInput(attrs={'class': 'form-control', 'placeholder': '/var/log/apache2/access.log'}),
        }
        
    def clean_file_path(self):
        file_path = self.cleaned_data['file_path']
        
        # Basic path validation
        if not file_path.endswith('.log'):
            raise forms.ValidationError("File path should end with .log")
            
        return file_path