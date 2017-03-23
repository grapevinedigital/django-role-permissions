from __future__ import unicode_literals

from django import template

from giaola_role_permissions.verifications import has_role, has_permission, has_object_permission

from giaola_role_permissions.shortcuts import retrieve_role_safely

from giaola_role_permissions.exceptions import RoleDoesNotExist

register = template.Library()


@register.filter(name='has_role')
def has_role_template_tag(user, role):
    role_list = role.split(',')
    return has_role(user, role_list)


@register.filter(name='can')
def can_template_tag(user, args):
    # Throws RoleDoesNotExist if an invalid role has been passed
    args = args.split(":")
    permission = args[0]
    role=None
    if len(args) > 1:
        role = retrieve_role_safely(args[1])

        if not role:
            raise RoleDoesNotExist

    return has_permission(user, permission, role)


@register.assignment_tag(name='can', takes_context=True)
def has_permission_template_tag(context, permission, obj, user=None):
    if not user:
        user = context.get('user')

    if user:
        return has_object_permission(permission, user, obj)

    return False
