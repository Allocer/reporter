# -*- coding: utf-8 -*-
# Generated by Django 1.10.1 on 2016-10-22 21:26
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('reporter', '0001_initial'),
    ]

    operations = [
        migrations.RenameField(
            model_name='malwarefile',
            old_name='malware_cependencies',
            new_name='malware_dependencies',
        ),
    ]