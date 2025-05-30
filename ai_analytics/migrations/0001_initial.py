# Generated by Django 5.1.5 on 2025-04-21 08:04

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('threat_detection', '0002_rename_active_detectionrule_enabled_and_more'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='AIReport',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=200)),
                ('report_type', models.CharField(choices=[('security_summary', 'Security Summary'), ('incident_analysis', 'Incident Analysis'), ('root_cause', 'Root Cause Analysis'), ('anomaly_detection', 'Anomaly Detection'), ('prediction', 'Predictive Analysis'), ('user_behavior', 'User Behavior Analysis'), ('cross_source', 'Cross-Source Correlation')], max_length=50)),
                ('content', models.TextField()),
                ('generated_at', models.DateTimeField(auto_now_add=True)),
                ('time_period_start', models.DateTimeField()),
                ('time_period_end', models.DateTimeField()),
                ('source_filter', models.CharField(blank=True, max_length=20, null=True)),
                ('severity_filter', models.CharField(blank=True, max_length=20, null=True)),
                ('is_cached', models.BooleanField(default=True)),
                ('cache_valid_until', models.DateTimeField()),
                ('tokens_used', models.IntegerField(default=0)),
                ('created_by', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='ai_reports', to=settings.AUTH_USER_MODEL)),
                ('related_incidents', models.ManyToManyField(blank=True, related_name='ai_reports', to='threat_detection.incident')),
                ('related_threats', models.ManyToManyField(blank=True, related_name='ai_reports', to='threat_detection.threat')),
            ],
            options={
                'verbose_name': 'AI Report',
                'verbose_name_plural': 'AI Reports',
                'ordering': ['-generated_at'],
            },
        ),
        migrations.CreateModel(
            name='AIReportFeedback',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('rating', models.IntegerField(choices=[(1, 'Poor'), (2, 'Fair'), (3, 'Good'), (4, 'Very Good'), (5, 'Excellent')])),
                ('comments', models.TextField(blank=True, null=True)),
                ('submitted_at', models.DateTimeField(auto_now_add=True)),
                ('report', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='feedback', to='ai_analytics.aireport')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.AddIndex(
            model_name='aireport',
            index=models.Index(fields=['report_type'], name='ai_analytic_report__efc142_idx'),
        ),
        migrations.AddIndex(
            model_name='aireport',
            index=models.Index(fields=['generated_at'], name='ai_analytic_generat_a6a41e_idx'),
        ),
        migrations.AddIndex(
            model_name='aireport',
            index=models.Index(fields=['time_period_start', 'time_period_end'], name='ai_analytic_time_pe_1713c3_idx'),
        ),
        migrations.AddIndex(
            model_name='aireport',
            index=models.Index(fields=['source_filter'], name='ai_analytic_source__30232d_idx'),
        ),
        migrations.AlterUniqueTogether(
            name='aireportfeedback',
            unique_together={('report', 'user')},
        ),
    ]
