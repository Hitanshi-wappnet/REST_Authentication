# Generated by Django 4.1.7 on 2023-03-16 07:20

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0001_initial'),
    ]

    operations = [
        migrations.DeleteModel(
            name='UserDetails',
        ),
    ]
