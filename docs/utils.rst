=====
Utils
=====

Shortcuts
=========

.. function:: get_user_role(user)

Returns the roles classes of the user.

.. code-block:: python

    from rolepermissions.shortcuts import get_user_roles

    roles = get_user_roles(user)

.. function:: assign_role(user, role)

Assigns a role to the user. Role parameter can be passed as string or role class object.

.. code-block:: python

    from rolepermissions.shortcuts import assign_role

    assign_role(user, 'doctor')

.. function:: remove_role(user)

Remove a role that was assigned to the specified user.

.. code-block:: python
    from rolepermissions.shortcuts import remove_role

    remove_role(user)

Remove all roles that was assigned to the specified user.

.. code-block:: python
    from rolepermissions.shortcuts import remove_all_roles

    remove_all_roles(user)

.. function:: available_perm_status(user)

Returns a dictionary containg all permissions per role available to the role of the specified user.
Role names are the keys of the dictionary with each role represented by another dictionary with permissions
as keys. The permissions values are ``True`` or ``False`` indicating if the permission if granted or not.

.. code-block:: python

    from rolepermissions.shortcuts import available_perm_status

    permissions = available_perm_status(user)

    if permissions['create_medical_record']:
        print 'user can create medical record'

.. function:: grant_permission(user, permission_name, role=None)

Grants a permission to a user for the given role. If no role passed, it will iterate through all roles of the given
user and try to grant the permission for each role that has it.
Will not grant a permission if the user doesn't have the role or the permission is not listed in the role's
``available_permissions``.

.. code-block:: python

    from rolepermissions.shortcuts import grant_permission

    grant_permission(user, 'create_medical_record', 'doctor')
    >>> True
    grant_permission(user, 'create_medical_record')
    >>> True


.. function:: revoke_permission(user, permission_name, role=None)

Revokes a permission for the given role. If no role passed, it will iterate through all roles to remove the permission
from each role that contains it.

.. code-block:: python

    from rolepermissions.shortcuts import revoke_permission

    revoke_permission(user, 'create_medical_record', 'doctor')
    >>> True
    revoke_permission(user, 'create_medical_record')
    >>> True


.. function:: get_permission_value(user, permission_name, role=None)

Get a permission value for the given role. If no role passed, it will iterate through all roles to retrieve the max value
for the permission from each role that contains it.

.. code-block:: python

    from rolepermissions.shortcuts import get_permission_value

    class LimitedRole(AbstractUserRole):
        available_permissions = { 'permission_limit':100 }

    get_permission_value(user, 'permission_limit', 'limited_role')
    >>> 100
    get_permission_value(user, 'permission_limit')
    >>> 100


Permission and role verification
================================

The following functions will always return ``True`` for users with supper_user status.

.. function:: has_role(user, roles)

Receives a user and a role and returns ``True`` if user has the specified role. Roles can be passed as
object, snake cased string representation or inside a list.

.. code-block:: python

    from rolepermissions.verifications import has_role
    from my_project.roles import Doctor

    if has_role(user, [Doctor, 'nurse']):
        print 'User is a Doctor or a nurse'

.. function:: has_permission(user, permission, role=None)

Receives a user and a permission and returns ``True`` is the user has ths specified permission for the role given. If no
role passed it will iterate through all user roles and will check if the user has the given permission for every role
that has the permission in the available_permissions list.

.. code-block:: python

    from rolepermissions.verifications import has_permission
    from my_project.roles import Doctor
    from records.models import MedicalRecord

    if has_permission(user, 'create_medical_record'):
        medical_record = MedicalRecord(...)
        medical_record.save()

    if has_permission(user, 'create_medical_record', 'doctor'):
        medical_record = MedicalRecord(...)
        medical_record.save()

.. _has-object-permission:

.. function:: has_object_permission(checker_name, user, obj)

Receives a string referencing the object permission checker, a user and the object to be verified.

.. code-block:: python

    from rolepermissions.verifications import has_object_permission
    from clinics.models import Clinic

    clinic = Clinic.objects.get(id=1)

    if has_object_permission('access_clinic', user, clinic):
        print 'access granted'


Template tags
=============

To load template tags use:

.. code-block:: python

    {% load permission_tags %}

.. function:: *filter* has_role

Receives a camel case representation of a role or more than one separated by coma.

.. code-block:: python

    {% load permission_tags %}
    {% if user|has_role:'doctor,nurse' %}
        the user is a doctor or a nurse
    {% endif %}

.. function:: *filter* can

Role permission filter. Role after permission is optional.

.. code-block:: python

    {% load permission_tags %}
    {% if user|can:'create_medical_record:doctor' %}
        <a href="/create_record">create record</a>
    {% endif %}

.. function:: *tag* can

If no user is passed to the tag, the logged user will be used in the verification.

.. code-block:: python

    {% load permission_tags %}

    {% can "access_clinic" clinic user=user as can_access_clinic %}
    {% if can_access_clinic %}
        <a href="/clinic/1/">Clinic</a>
    {% endif %}
