# Generated by Django 5.1.3 on 2024-11-16 05:13

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('admin_panel', '0002_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='childrecord',
            name='recommandations',
            field=models.TextField(blank=True, null=True),
        ),
    ]