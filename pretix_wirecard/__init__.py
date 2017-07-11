from django.apps import AppConfig


class PluginApp(AppConfig):
    name = 'pretix_wirecard'
    verbose_name = 'pretix Wirecard integration'

    class PretixPluginMeta:
        name = 'pretix Wirecard integration'
        author = 'Raphael Michel'
        description = 'This plugin integrates Wirecard payment methods with pretix'
        visible = True
        version = '0.5.1'

    def ready(self):
        from . import signals  # NOQA


default_app_config = 'pretix_wirecard.PluginApp'
