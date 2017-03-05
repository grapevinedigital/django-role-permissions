from __future__ import unicode_literals

import inspect

from django.core.exceptions import ObjectDoesNotExist

from rolepermissions.roles import RolesManager
from rolepermissions.permissions import PermissionsManager
from rolepermissions.shortcuts import get_user_roles, get_permission


def has_role(user, roles):
    if user and user.is_superuser:
        return True

    if not isinstance(roles, list):
        roles = [roles]

    normalized_roles = []
    for role in roles:
        if not inspect.isclass(role):
            role = RolesManager.retrieve_role(role)

        normalized_roles.append(role)

    user_roles = get_user_roles(user)

    if user_roles:
        has_roles = True
        for role in normalized_roles:
            has_roles = has_roles and role in user_roles
        return has_roles

    return False


def has_permission(user, permission_name, role=None):
    # if superuser return true.
    # if role and user has permission for the given role return true.
    # else go through all roles and return true only if user has
    # permission for all roles
    if user and user.is_superuser:
        return True

    if role:
        return __has_permission__(user, permission_name, role)
    else:
        _perm = True

        for role in get_user_roles(user):
            _perm = _perm and __has_permission__(user, permission_name, role)

        return _perm


def __has_permission__(user, permission_name, role):
    if role and permission_name in role.permission_names_list():
        permission = get_permission(
            role.get_permission_name(permission_name))

        if permission in user.user_permissions.all():
            return True
    return False


def has_object_permission(checker_name, user, obj):
    if user.is_superuser:
        return True

    checker = PermissionsManager.retrieve_checker(checker_name)
    roles = get_user_roles(user)

    return checker(roles, user, obj)
