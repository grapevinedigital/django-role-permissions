from __future__ import unicode_literals

from six import add_metaclass

from django.contrib.auth.models import Group, Permission
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType

from giaola_role_permissions.utils import camelToSnake


registered_roles = {}


class RolesManager(object):

    def __iter__(cls):
        return iter(registered_roles)

    @classmethod
    def retrieve_role(cls, role_name):
        if role_name in registered_roles:
            return registered_roles[role_name]

        return None

    @classmethod
    def get_roles_names(cls):
        return registered_roles.keys()


class RolesClassRegister(type):

    def __new__(cls, name, parents, dct):
        role_class = super(RolesClassRegister, cls).__new__(cls, name, parents, dct)
        if object not in parents:
            registered_roles[role_class.get_name()] = role_class
        return role_class


@add_metaclass(RolesClassRegister)
class AbstractUserRole(object):

    @classmethod
    def get_name(cls):
        if hasattr(cls, 'role_name'):
            return cls.role_name

        return camelToSnake(cls.__name__)

    @classmethod
    def get_available_permissions(cls):
        return getattr(cls, 'available_permissions', {})

    @classmethod
    def get_available_permissions_names_list(cls):
        available_permissions = getattr(cls, 'available_permissions', {})
        return [key for (key, value) in available_permissions.items()]

    @classmethod
    def get_permission_db_name(cls, permission_name):
        return "{0}.{1}".format(cls.get_name(), permission_name)

    @classmethod
    def get_available_permission_db_names_list(cls):
        available_permissions = getattr(cls, 'available_permissions', {})
        return [cls.get_permission_db_name(key) for (key, value) in available_permissions.items()]

    @classmethod
    def get_role_limit(cls):
        return getattr(cls, 'role_limit', None)

    @classmethod
    def get_permission_limit(cls, permission_name):
        if permission_name not in cls.get_available_permissions_names_list():
            return None

        permission_limits = getattr(cls, 'available_permissions_limits', {})
        return permission_limits.get(permission_name, None)

    @classmethod
    def assign_role_to_user(cls, user):
        """
        Assigns a role the user.

        :returns: :py:class:`django.contrib.auth.models.Group` The group for the
            new role.
        """
        # max comment: we comment out the following 2 lines since we want to support multiple roles
        # from giaola_role_permissions.shortcuts import remove_role
        # remove_role(user)

        group, created = Group.objects.get_or_create(name=cls.get_name())
        user.groups.add(group)
        permissions_to_add = cls.get_default_true_permissions()
        user.user_permissions.add(*permissions_to_add)

        return group


    @classmethod
    def remove_role_from_user(cls, user):
        """
        Deletes role from user.

        :returns: :py:class:`django.contrib.auth.models.Group` if the role was in the user's roles or None.

        :return:
        """
        group = Group.objects.get(name=cls.get_name())
        if group:
            permissions = Permission.objects.filter(codename__in=cls.get_available_permission_db_names_list())
            user.user_permissions.remove(*permissions)
            user.groups.remove(group)
            return group

        return None

    @classmethod
    def get_default_true_permissions(cls):
        if hasattr(cls, 'available_permissions'):

            permission_names = [cls.get_permission_db_name(key)
                                for (key, default) in cls.available_permissions.items() if default]

            return cls.get_or_create_permissions(permission_names)

        return []

    @classmethod
    def get_or_create_permissions(cls, permission_names):
        user_ct = ContentType.objects.get_for_model(get_user_model())
        permissions = list(Permission.objects.filter(
            content_type=user_ct, codename__in=permission_names).all())

        if len(permissions) != len(permission_names):
            for permission_name in permission_names:
                permission, created = Permission.objects.get_or_create(
                    content_type=user_ct, codename=permission_name)
                if created:
                    permissions.append(permission)

        return permissions

    @classmethod
    def get_default(cls, permission_name):
        return cls.available_permissions[permission_name]
