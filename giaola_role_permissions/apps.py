
from django.apps import AppConfig

from giaola_role_permissions.loader import load_roles_and_permissions


class RolePermissions(AppConfig):
    name = 'giaola_role_permissions'
    verbose_name = "Django Role Permissions"

    def ready(self):
        load_roles_and_permissions()
