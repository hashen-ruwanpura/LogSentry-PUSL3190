# Generated by Django 5.1.5 on 2025-04-15 18:45

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('siem', '0001_initial'),
    ]

    operations = [
        # Order matters - delete SecurityAlert first as it has FKs to the others
        migrations.DeleteModel(
            name='SecurityAlert',
        ),
        migrations.DeleteModel(
            name='ApacheLogEntry',
        ),
        migrations.DeleteModel(
            name='MySQLLogEntry',
        ),
    ]
