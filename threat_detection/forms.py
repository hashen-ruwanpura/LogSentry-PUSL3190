from django import forms
from .models import DetectionRule, Threat, Incident

class DetectionRuleForm(forms.ModelForm):
    class Meta:
        model = DetectionRule
        fields = ['name', 'rule_type', 'pattern', 'description', 'severity', 'is_active']

class ThreatUpdateForm(forms.ModelForm):
    class Meta:
        model = Threat
        fields = ['status', 'severity', 'notes']

class IncidentForm(forms.ModelForm):
    class Meta:
        model = Incident
        fields = ['title', 'description', 'status', 'severity', 'assigned_to', 'related_threats']