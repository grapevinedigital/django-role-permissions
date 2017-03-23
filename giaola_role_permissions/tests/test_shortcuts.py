from django.test import TestCase
from django.contrib.auth import get_user_model

from model_mommy import mommy

from giaola_role_permissions.roles import RolesManager, AbstractUserRole
from giaola_role_permissions.shortcuts import (
    get_user_roles, grant_permission,
    revoke_permission, retrieve_role,
    available_perm_status, assign_role,
    remove_role, get_role_limit, get_permission_limit
)
from giaola_role_permissions.verifications import has_permission
from giaola_role_permissions.exceptions import RoleDoesNotExist


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

class ShoRole4(AbstractUserRole):
    role_limit = 111

    available_permissions = {
        'permission7': False,
        'permission8': False,
    }

    available_permissions_limits = {
        'permission7': 21,
        'whatever_permission': 293
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

class GetRoleLimitsTest(TestCase):

    def test_get_role_limit(self):
        self.assertEqual(get_role_limit('sho_role4'), 111)

    def test_get_non_existent_role_limit(self):
        self.assertEqual(get_role_limit('sho_role2'), None)

class GetPermissionLimitTest(TestCase):

    def test_get_permission_limit(self):
        self.assertEqual(get_permission_limit('sho_role4', 'permission7'), 21)

    def test_get_non_existent_permission_limit(self):
        self.assertEqual(get_permission_limit('sho_role4', 'permission9'), None)

    def test_get_non_existent_permission_limit(self):
        self.assertEqual(get_permission_limit('sho_role4', 'whatever_permission'), None)

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
