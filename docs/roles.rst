=====
Roles
=====

Roles File
==========

Create a ``roles.py`` file anywhere inside your django project and reference it in the project settings file.

``my_project/roles.py``

.. code-block:: python

    from rolepermissions.roles import AbstractUserRole

    class Doctor(AbstractUserRole):
        available_permissions = {
            'create_medical_record': True,
        }

    class Nurse(AbstractUserRole):
        available_permissions = {
            'edit_patient_file': True,
        }

``settings.py``

.. code-block:: python

    ROLEPERMISSIONS_MODULE = 'my_project.roles'

Each class that imports ``AbstractUserRole`` is a role on the project and has a snake case string representation.
For example:

.. code-block:: python

    from rolepermissions.roles import AbstractUserRole

    class SystemAdmin(AbstractUserRole):
        available_permissions = {
            'drop_tables': True,
        }

will have the string representation: ``system_admin``.

Available Role Permissions
==========================

The field ``available_permissions`` lists what permissions the role can be granted.
The boolean referenced on the ``available_permissions`` dictionary is the default value to the
referred permission.

Role Limits
===========

The field ``role_limits`` contains a limit (whatever object you want) the role has.

.. code-block:: python

    from rolepermissions.roles import AbstractUserRole

    class SystemAdmin(AbstractUserRole):
        available_permissions = {
            'drop_tables': True,
        }
        role_limit = 100

or

.. code-block:: python

    from rolepermissions.roles import AbstractUserRole

    class SystemAdmin(AbstractUserRole):
        available_permissions = {
            'drop_tables': True,
        }
        role_limit = { 'create_offers': 10, 'create_auctions': 20 }

Role limits can be accessed

.. code-block:: python


    system_admin_role_limits = SystemAdmin.get_role_limit()

Available Permissions Limits
============================

The field ``available_permissions_limit`` lists the limits for the permissions of the role. It is not mandatory to
have a limit for each permission.

.. code-block:: python

    from rolepermissions.roles import AbstractUserRole

    class SystemAdmin(AbstractUserRole):
        available_permissions = {
            'create_offers': True,
            'create_auctions': True,
        }
        available_permissions_limits = {
            'create_offers': 10,
            'create_auctions': 20
        }
Can be accessed as follow

.. code-block:: python


    system_admin_create_offers_limit = SystemAdmin.get_permission_limit('create_offers')

