# Generated by Django 5.1.1 on 2025-01-11 09:23

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('App1', '0006_remove_services_service_name_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='services',
            name='Rate',
            field=models.IntegerField(null=True),
        ),
        migrations.AlterField(
            model_name='services',
            name='Service_details',
            field=models.TextField(null=True),
        ),
    ]
