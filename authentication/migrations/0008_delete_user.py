# Generated by Django 4.1.7 on 2023-03-16 13:51

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0007_remove_user_verified_alter_user_otp'),
    ]

    operations = [
        migrations.DeleteModel(
            name='User',
        ),
    ]
