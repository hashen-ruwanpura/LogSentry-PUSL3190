from django.db import models


class Threat(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField()
    detected_at = models.DateTimeField(auto_now_add=True)

class Incident(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField()
    detected_at = models.DateTimeField(auto_now_add=True)

class Log(models.Model):
    source = models.CharField(max_length=100)
    message = models.TextField()
    logged_at = models.DateTimeField(auto_now_add=True)
