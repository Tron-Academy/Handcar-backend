# Generated by Django 5.1.1 on 2025-01-11 08:39

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('App1', '0002_delete_vendor_services_address_services_created_at_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='ServiceCategory',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255, unique=True)),
            ],
        ),
    ]
