from django.test import TestCase
from django.contrib.auth import get_user_model
from django.template import Context, Template

from model_mommy import mommy

from giaola_role_permissions.roles import RolesManager, AbstractUserRole
from giaola_role_permissions.templatetags.permission_tags import has_role_template_tag
from giaola_role_permissions.exceptions import RoleDoesNotExist


class TemRole1(AbstractUserRole):
    available_permissions = {
        'permission1': True,
        'permission2': True,
    }

class TemRole2(AbstractUserRole):
    available_permissions = {
        'permission3': True,
        'permission4': False,
    }

class TemRole3(AbstractUserRole):
    role_name = 'new_name'
    available_permissions = {
        'permission5': False,
        'permission6': False,
    }


class HasRoleTests(TestCase):

    def setUp(self):
        self.user = mommy.make(get_user_model())

        TemRole1.assign_role_to_user(self.user)
        # Use this to simulate register
        TemRole3.assign_role_to_user(self.user)
        TemRole3.remove_role_from_user(self.user)

    def tag_test(self, template, context, output):
        t = Template('{% load permission_tags %}'+template)
        c = Context(context)
        self.assertEqual(t.render(c), output)

    def test_has_role_tag(self):
        user = self.user

        template = '{% if user|has_role:"tem_role1" %}passed{% endif %}'

        context = {
            'user': user,
        }

        output = 'passed'

        self.tag_test(template, context, output)

    def test_has_role_tag_with_multiple_roles(self):
        user = self.user

        template = '{% if user|has_role:"tem_role1,tem_role2" %}passed{% endif %}'

        context = {
            'user': user,
        }

        output = 'passed'

        self.tag_test(template, context, output)

    def test_does_not_have_role_tag_with_multiple_roles(self):
        user = self.user

        template = '{% if user|has_role:"tem_role2,tem_role3" %}passed{% endif %}'

        context = {
            'user': user,
        }

        output = ''

        self.tag_test(template, context, output)

    def test_has_permission(self):
        user = self.user

        template = '{% if user|can:"permission1" %}passed{% endif %}'

        context = {
            'user': user
        }

        output = 'passed'

        self.tag_test(template, context, output)

    def test_has_permission_with_role(self):
        user = self.user

        template = '{% if user|can:"permission1:tem_role1" %}passed{% endif %}'

        context = {
            'user': user
        }

        output = 'passed'

        self.tag_test(template, context, output)

    def test_has_permission_not_in_role(self):
        user = self.user

        template = '{% if user|can:"permission1:new_name" %}passed{% endif %}'

        context = {
            'user': user
        }

        output = ''
        self.tag_test(template, context, output)
