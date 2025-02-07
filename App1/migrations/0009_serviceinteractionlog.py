# Generated by Django 5.1.1 on 2025-01-11 12:21

import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('App1', '0008_rename_image_services_image_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='ServiceInteractionLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('action', models.CharField(choices=[('CALL', 'Call'), ('WHATSAPP', 'WhatsApp Message')], max_length=10)),
                ('timestamp', models.DateTimeField(default=django.utils.timezone.now)),
                ('user_ip', models.GenericIPAddressField(blank=True, null=True)),
                ('service', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='interaction_logs', to='App1.services')),
            ],
            options={
                'verbose_name': 'Service Interaction Log',
                'verbose_name_plural': 'Service Interaction Logs',
                'ordering': ['-timestamp'],
            },
        ),
    ]
