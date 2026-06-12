# Generated migration for adding session_id to PromptLog

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0003_rename_api_promptl_event_t_270ae6_idx_api_promptl_event_t_8b269d_idx_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='promptlog',
            name='session_id',
            field=models.CharField(blank=True, db_index=True, default='', max_length=64),
        ),
    ]
