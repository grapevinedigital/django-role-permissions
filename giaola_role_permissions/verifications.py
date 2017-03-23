from __future__ import unicode_literals

import inspect

from django.core.exceptions import ObjectDoesNotExist

from giaola_role_permissions.roles import RolesManager
from giaola_role_permissions.permissions import PermissionsManager
from giaola_role_permissions.shortcuts import retrieve_role_safely, get_user_roles, get_permission


def has_role(user, roles):
    # Returns true if the user has at least one of the roles given
    # Roles can be an array or just a role
    if user and user.is_superuser:
        return True

    if not isinstance(roles, list):
        roles = [roles]

    normalized_roles = []
    for role in roles:
        role = retrieve_role_safely(role)
        normalized_roles.append(role)

    user_roles = get_user_roles(user)

    if user_roles:
        for role in normalized_roles:
            if role in user_roles:
                return True
    return False

def has_roles(user, roles):
    # Returns true if the user has all of the roles given
    # Roles can be an array or just a role
    if user and user.is_superuser:
        return True

    if not isinstance(roles, list):
        roles = [roles]

    normalized_roles = []
    for role in roles:
        role = retrieve_role_safely(role)
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
    # permission for all roles that have the permission in their list.

    if not user:
        return False

    if user.is_superuser:
        return True

    if not permission_name:
        return False

    if role:
        role = retrieve_role_safely(role)
        return __has_permission_for_role__(user, permission_name, role)

    return __has_permission__(user, permission_name)

def __has_permission_for_role__(user, permission_name, role):
    permission = get_permission(
        role.get_permission_db_name(permission_name))

    if permission in user.user_permissions.all():
        return True

    return False

def __has_permission__(user, permission_name):
    user_roles = get_user_roles(user)

    if len(user_roles) == 0:
        return False

    permission_in_role_count = 0
    permission_true_in_role_count = 0
    for role in user_roles:
        if permission_name in role.get_available_permissions_names_list():
            permission_in_role_count += 1
        if __has_permission_for_role__(user, permission_name, role):
            permission_true_in_role_count += 1

    return permission_in_role_count != 0 and \
           permission_in_role_count == permission_true_in_role_count


def has_object_permission(checker_name, user, obj):
    if user.is_superuser:
        return True

    checker = PermissionsManager.retrieve_checker(checker_name)
    roles = get_user_roles(user)

    return checker(roles, user, obj)
