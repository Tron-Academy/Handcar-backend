# Generated by Django 5.1.1 on 2024-11-27 07:27

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('App1', '0009_remove_brand_description_remove_category_description'),
    ]

    operations = [
        migrations.AlterField(
            model_name='product',
            name='name',
            field=models.CharField(max_length=2000),
        ),
    ]
