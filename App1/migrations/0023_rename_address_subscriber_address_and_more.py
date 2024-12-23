# Generated by Django 5.1.1 on 2024-12-23 10:39

import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('App1', '0022_rename_location_vendor_address_and_more'),
    ]

    operations = [
        migrations.RenameField(
            model_name='subscriber',
            old_name='Address',
            new_name='address',
        ),
        migrations.RenameField(
            model_name='vendor',
            old_name='Address',
            new_name='address',
        ),
        migrations.AddField(
            model_name='subscriber',
            name='latitude',
            field=models.FloatField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='subscriber',
            name='longitude',
            field=models.FloatField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='vendor',
            name='created_at',
            field=models.DateTimeField(default=django.utils.timezone.now),
        ),
        migrations.AddField(
            model_name='vendor',
            name='latitude',
            field=models.FloatField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='vendor',
            name='longitude',
            field=models.FloatField(blank=True, null=True),
        ),
    ]
