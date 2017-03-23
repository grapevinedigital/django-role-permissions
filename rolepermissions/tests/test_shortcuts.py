from django.test import TestCase
from django.contrib.auth import get_user_model

from model_mommy import mommy

from rolepermissions.roles import RolesManager, AbstractUserRole
from rolepermissions.shortcuts import (
    get_user_roles, grant_permission,
    revoke_permission, retrieve_role,
    available_perm_status, assign_role,
    remove_role, limit_passed, get_limit
)
from rolepermissions.verifications import has_permission
from rolepermissions.exceptions import RoleDoesNotExist


class ShoRole1(AbstractUserRole):
    available_permissions = {
        'permission1': True,
        'permission2': True,
    }


class ShoRole2(AbstractUserRole):
    available_permissions = {
        'permission3': True,
        'permission4': False,
    }


class ShoRole3(AbstractUserRole):
    role_name = 'sho_new_name'
    available_permissions = {
        'permission5': False,
        'permission6': False,
    }


class LimitedRole(AbstractUserRole):
    available_permissions = {
        'permission5': False,
        'permission6': False,
    }
    limits = {
        'model:attribute': 10,
        'general_limit': 100
    }


class AssignRole(TestCase):

    def setUp(self):
        self.user = mommy.make(get_user_model())

    def test_assign_role(self):
        user = self.user

        assign_role(user, 'sho_role1')

        self.assertIn(ShoRole1, get_user_roles(user))

    def test_assign_role_by_class(self):
        user = self.user

        assign_role(user, ShoRole1)

        self.assertIn(ShoRole1, get_user_roles(user))

    def test_assign_invalid_role(self):
        user = self.user

        with self.assertRaises(RoleDoesNotExist):
            assign_role(user, 'no role')


class RemoveRole(TestCase):

    def setUp(self):
        self.user = mommy.make(get_user_model())

    def test_user_has_no_role(self):
        user = self.user

        assign_role(user, ShoRole1.get_name())
        remove_role(user, ShoRole1.get_name())

        self.assertNotIn(ShoRole1, get_user_roles(user))


class GetUserRolesTests(TestCase):

    def setUp(self):
        self.user = mommy.make(get_user_model())

    def test_get_user_role(self):
        user = self.user

        ShoRole1.assign_role_to_user(user)

        self.assertIn(ShoRole1, get_user_roles(user))

    def test_get_user_role_after_role_change(self):
        user = self.user

        ShoRole1.assign_role_to_user(user)
        ShoRole3.assign_role_to_user(user)

        self.assertIn(ShoRole1, get_user_roles(user))
        self.assertIn(ShoRole3, get_user_roles(user))

    def test_user_without_role(self):
        user = self.user

        self.assertEquals(get_user_roles(user), [])

    def tearDown(self):
        RolesManager._roles = {}


class AvailablePermStatusTests(TestCase):

    def setUp(self):
        self.user = mommy.make(get_user_model())
        self.user_role = ShoRole2.assign_role_to_user(self.user)

    def test_permission_hash(self):
        perm_hash = available_perm_status(self.user)

        self.assertTrue(perm_hash[ShoRole2.get_name()]['permission3'])
        self.assertFalse(perm_hash[ShoRole2.get_name()]['permission4'])

    def test_permission_hash_after_modification(self):
        revoke_permission(self.user, 'permission3')

        perm_hash = available_perm_status(self.user)

        self.assertFalse(perm_hash[ShoRole2.get_name()]['permission3'])
        self.assertFalse(perm_hash[ShoRole2.get_name()]['permission4'])


class GrantPermissionTests(TestCase):

    def setUp(self):
        self.user = mommy.make(get_user_model())
        self.user_role2 = ShoRole2.assign_role_to_user(self.user)
        self.user_role3 = ShoRole3.assign_role_to_user(self.user)

    def test_grant_permission(self):
        user = self.user

        self.assertTrue(grant_permission(user, 'permission4'))

        self.assertTrue(has_permission(user, 'permission4'))

    def test_grant_permission_for_role(self):
        user = self.user

        self.assertTrue(grant_permission(user, 'permission5', ShoRole3))

        self.assertTrue(has_permission(user, 'permission5', ShoRole3))

    def test_grant_permission_for_role_by_name(self):
        user = self.user

        self.assertTrue(grant_permission(user, 'permission6', ShoRole3.get_name()))

        self.assertTrue(has_permission(user, 'permission6', ShoRole3.get_name()))


    def test_grant_granted_permission(self):
        user = self.user

        self.assertTrue(grant_permission(user, 'permission3'))

        self.assertTrue(has_permission(user, 'permission3'))

    def test_not_allowed_permission_no_role(self):
        user = self.user

        self.assertFalse(grant_permission(user, 'permission1'))

    def test_not_allowed_permission_in_role(self):
        user = self.user

        self.assertFalse(grant_permission(user, 'permission1', ShoRole1))

    def test_not_allowed_permission_in_role_by_name(self):
        user = self.user

        self.assertFalse(grant_permission(user, 'permission1', ShoRole1.get_name()))

    def test_not_allowed_permission_not_in_role_by_name(self):
        user = self.user

        self.assertFalse(grant_permission(user, 'not-in-role-permission', ShoRole3.get_name()))


class RevokePermissionTests(TestCase):

    def setUp(self):
        self.user = mommy.make(get_user_model())
        self.user_role = ShoRole2.assign_role_to_user(self.user)

    def test_revoke_permission(self):
        user = self.user

        self.assertTrue(revoke_permission(user, 'permission3'))

        self.assertFalse(has_permission(user, 'permission3'))

    def test_revoke_revoked_permission(self):
        user = self.user

        self.assertTrue(revoke_permission(user, 'permission4'))

        self.assertFalse(has_permission(user, 'permission4'))

    def test_not_allowed_permission(self):
        user = self.user

        self.assertFalse(revoke_permission(user, 'permission1'))


class LimitPassedTests(TestCase):

    def setUp(self):
        self.user = mommy.make(get_user_model())
        LimitedRole.assign_role_to_user(self.user)

    def test_limit_passed(self):
        self.assertTrue(limit_passed(self.user, 'model:attribute', 11))
        self.assertTrue(limit_passed(self.user, 'model:attribute', 11, LimitedRole.get_name()))

    def test_limit_passed_false(self):
        self.assertFalse(limit_passed(self.user, 'model:attribute', 5))
        self.assertFalse(limit_passed(self.user, 'model:attribute', 5, LimitedRole.get_name()))
    
    def test_limit_passed_equals_to_value(self):
        self.assertFalse(limit_passed(self.user, 'model:attribute', 10))
        self.assertFalse(limit_passed(self.user, 'model:attribute', 10, LimitedRole.get_name()))
        
    def test_limit_passed_role_not_in_roles(self):
        self.assertFalse(limit_passed(self.user, 'model:attribute', 5, ShoRole3.get_name()))

    def test_limit_passed_user_without_roles(self):
        remove_role(self.user, LimitedRole.get_name())
        self.assertFalse(limit_passed(self.user, 'model:attribute', 5))

        self.assertFalse(limit_passed(self.user, 'model:attribute', 5, LimitedRole.get_name()))

    def test_limit_passed_role_without_limits(self):
        ShoRole3.assign_role_to_user(self.user)
        remove_role(self.user, LimitedRole.get_name())

        self.assertFalse(limit_passed(self.user, 'model:attribute', 1000, ShoRole3.get_name()))
        self.assertFalse(limit_passed(self.user, 'model:attribute', 1000))


class GetLimitTests(TestCase):
    def setUp(self):
        self.user = mommy.make(get_user_model())
        LimitedRole.assign_role_to_user(self.user)

    def test_get_limit(self):
        self.assertEquals(10, get_limit(self.user, 'model:attribute'))
        self.assertTrue(10, get_limit(self.user, 'model:attribute', LimitedRole.get_name()))

    def test_get_limit_none(self):
        self.assertIsNone(get_limit(self.user, 'model:attribute2'))
        self.assertIsNone(get_limit(self.user, 'model:attribute2', LimitedRole.get_name()))

    def test_get_limit_role_not_in_roles(self):
        with self.assertRaises(RoleDoesNotExist):
            get_limit(self.user, 'model:attribute', ShoRole3.get_name())

    def test_get_limit_user_without_roles(self):
        remove_role(self.user, LimitedRole.get_name())
        with self.assertRaises(RoleDoesNotExist):
            get_limit(self.user, 'model:attribute')

        with self.assertRaises(RoleDoesNotExist):
            get_limit(self.user, 'model:attribute', LimitedRole.get_name())

    def test_get_limit_role_without_limits(self):
        ShoRole3.assign_role_to_user(self.user)
        remove_role(self.user, LimitedRole.get_name())

        self.assertIsNone(get_limit(self.user, 'model:attribute', ShoRole3.get_name()))
        self.assertIsNone(get_limit(self.user, 'model:attribute'))


class RetrieveRole(TestCase):

    def setUp(self):
        pass

    def test_retrieve_role1(self):
        self.assertEquals(retrieve_role('sho_role1'), ShoRole1)

    def test_retrieve_role2(self):
        self.assertEquals(retrieve_role('sho_role2'), ShoRole2)

    def test_retrieve_role3(self):
        self.assertEquals(retrieve_role('sho_new_name'), ShoRole3)

    def test_retrieve_unknown_role(self):
        role = retrieve_role('unknown_role')
        self.assertIsNone(role)


class Buyer(AbstractUserRole):
    available_permissions = {
        'offersale_can_create': True,
        'offer_can_read': True,
        'admin_can_update': True,
        'admin_can_delete': True,
    }


class AdminReadOnly(AbstractUserRole):
    available_permissions = {
        'admin_can_create': False,
        'admin_can_read': True,
        'admin_can_update': False,
        'admin_can_delete': False,
    }


# This maybe should be passed to giaola apps
class ExtremeCases(TestCase):

    def setUp(self):
        pass

    def test_has_permission_with_two_roles(self):
        user = mommy.make(get_user_model())

        assign_role(user, 'buyer')

        self.assertEquals(get_user_roles(user), [Buyer])
        self.assertTrue(has_permission(user,'offersale_can_create'))

        assign_role(user, 'admin_read_only')

        self.assertEquals(set(get_user_roles(user)), set([Buyer, AdminReadOnly]))
        self.assertTrue(has_permission(user, 'offersale_can_create'))

    def tearDown(self):
        pass
