from __future__ import unicode_literals

import inspect

from django.contrib.contenttypes.models import ContentType
from django.contrib.auth.models import Permission
from django.contrib.auth import get_user_model

from giaola_role_permissions.roles import RolesManager, registered_roles
from giaola_role_permissions.exceptions import RoleDoesNotExist


# Roles

def retrieve_role(role_name):
    return RolesManager.retrieve_role(role_name)

def retrieve_role_safely(role):
    role_cls = role

    if not inspect.isclass(role):
        role_cls = retrieve_role(role)

    return role_cls

def get_user_roles(user):
    if user:
        return [RolesManager.retrieve_role(group.name)
                for group in user.groups.filter(name__in=RolesManager.get_roles_names())]
    return None


def assign_role(user, role):
    role_cls = retrieve_role_safely(role)

    if not role_cls:
        raise RoleDoesNotExist

    role_cls.assign_role_to_user(user)

    return role_cls


def remove_all_roles(user):
    # removes all roles from the given user and
    # all the permissions associated with the roles
    groups = user.groups.filter(name__in=registered_roles.keys())
    for group in groups:  # Normally there is only one, but remove all other role groups
        role = RolesManager.retrieve_role(group.name)
        group_permissions = [role.get_permission_db_name(permission_name)
                             for permission_name in role.get_available_permission_db_names_list()]
        permissions_to_remove = Permission.objects.filter(codename__in=group_permissions).all()
        user.user_permissions.remove(*permissions_to_remove)
    user.groups.remove(*groups)


def remove_role(user, role):
    # removes the given role from the user and all
    # the permissions associated with the role
    role = retrieve_role_safely(role)

    if not role:
        raise RoleDoesNotExist

    old_group = user.groups.filter(name__exact=role.get_name()).first()
    if old_group:
        role_permissions = [role.get_permission_db_name(permission_name)
                            for permission_name in role.get_available_permission_db_names_list()]
        permissions_to_remove = Permission.objects.filter(codename__in=role_permissions)
        user.user_permissions.remove(*permissions_to_remove)
        user.groups.remove(old_group)


# Permissions


def get_permission(permission_name):
    user_ct = ContentType.objects.get_for_model(get_user_model())
    permission, created = Permission.objects.get_or_create(
        content_type=user_ct,
        codename=permission_name)

    return permission


def available_perm_status(user):
    from giaola_role_permissions.verifications import has_permission

    roles = get_user_roles(user)

    permission_hash = {}

    if roles:
        for role in roles:
            permission_names = role.get_available_permissions_names_list()
            for permission_name in permission_names:
                has_perm = has_permission(user, permission_name, role)
                permission_hash\
                    .setdefault(role.get_name(), {})\
                    .setdefault(permission_name, has_perm)

    return permission_hash


def grant_permission(user, permission_name, role=None):
    # grants the given permission from the user
    # if a valid role is given only the permission
    # from that role will be revoked.
    roles = get_user_roles(user)

    if not roles:
        return False

    if role:
        role_cls = retrieve_role_safely(role)

        if not role_cls:
            raise RoleDoesNotExist

        if role_cls in roles and permission_name in role_cls.get_available_permissions_names_list():
            permission = get_permission(
                role_cls.get_permission_db_name(permission_name))
            user.user_permissions.add(permission)
            return True

        return False
    else:
        permissions_granted_count = 0
        for role in roles:
            if permission_name in role.get_available_permissions_names_list():
                permission = get_permission(
                    role.get_permission_db_name(permission_name))
                user.user_permissions.add(permission)
                permissions_granted_count += 1
        return permissions_granted_count > 0


def revoke_permission(user, permission_name, role=None):
    # grants the given permission from the user
    # if a valid role is given only the permission
    # from that role will be revoked.
    roles = get_user_roles(user)

    if not roles:
        return False

    if role:
        role_cls = role

        if not inspect.isclass(role):
            role_cls = retrieve_role(role)

        if not role_cls:
            raise RoleDoesNotExist

        if role_cls in roles and role_cls in roles and \
                permission_name in role_cls.get_available_permission_db_names_list():
            permission = get_permission(
                role_cls.get_permission_db_name(permission_name))
            user.user_permissions.remove(permission)

            return True

        return False
    else:
        permissions_revoked_count = 0
        for role in roles:
            if permission_name in role.get_available_permissions_names_list():
                permission = get_permission(
                    role.get_permission_db_name(permission_name))
                user.user_permissions.remove(permission)
                permissions_revoked_count += 1
        return permissions_revoked_count > 0

def get_role_limit(role):
    role = retrieve_role_safely(role)

    if not role:
        raise RoleDoesNotExist

    return role.get_role_limit()

def get_permission_limit(role, permission_name):
    role = retrieve_role_safely(role)

    if not role:
        raise RoleDoesNotExist

    return role.get_permission_limit(permission_name)

