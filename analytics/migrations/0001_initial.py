# Generated by Django 5.1.5 on 2025-04-04 05:16

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='LogReport',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('timestamp', models.DateTimeField()),
                ('log_type', models.CharField(choices=[('apache', 'Apache'), ('mysql', 'MySQL')], max_length=20)),
                ('source_ip', models.GenericIPAddressField()),
                ('country_code', models.CharField(blank=True, max_length=2, null=True)),
                ('country_name', models.CharField(blank=True, max_length=100, null=True)),
                ('threat_type', models.CharField(max_length=100)),
                ('severity', models.CharField(choices=[('high', 'High'), ('medium', 'Medium'), ('low', 'Low')], max_length=10)),
                ('status', models.CharField(choices=[('open', 'Open'), ('in_progress', 'In Progress'), ('resolved', 'Resolved')], default='open', max_length=20)),
                ('raw_log', models.TextField()),
                ('request_method', models.CharField(blank=True, max_length=10, null=True)),
                ('request_path', models.TextField(blank=True, null=True)),
                ('status_code', models.IntegerField(blank=True, null=True)),
                ('response_size', models.IntegerField(blank=True, null=True)),
                ('user_agent', models.TextField(blank=True, null=True)),
                ('database', models.CharField(blank=True, max_length=100, null=True)),
                ('query_type', models.CharField(blank=True, max_length=50, null=True)),
                ('notes', models.TextField(blank=True, null=True)),
                ('resolved_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('resolved_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='resolved_reports', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-timestamp'],
                'indexes': [models.Index(fields=['timestamp'], name='analytics_l_timesta_9139d9_idx'), models.Index(fields=['log_type'], name='analytics_l_log_typ_723291_idx'), models.Index(fields=['severity'], name='analytics_l_severit_ef6162_idx'), models.Index(fields=['status'], name='analytics_l_status_56997b_idx'), models.Index(fields=['source_ip'], name='analytics_l_source__8da34d_idx')],
            },
        ),
    ]
