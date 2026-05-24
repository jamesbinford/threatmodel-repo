from django.contrib.auth.models import Group, User
from django.test import TestCase

from apps.organization.models import BusinessUnit
from .models import RoleMapping


class RoleMappingTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(username='analyst', password='pass12345')
        cls.group = Group.objects.create(name='Threat Model Contributors')
        cls.business_unit = BusinessUnit.objects.create(name='Payments', slug='payments')

    def test_active_django_group_mapping_applies_to_group_member(self):
        self.user.groups.add(self.group)
        mapping = RoleMapping.objects.create(
            name='Payment Contributors',
            group=self.group,
            role=RoleMapping.ROLE_CONTRIBUTOR,
            business_unit=self.business_unit,
        )

        self.assertTrue(mapping.applies_to_user(self.user))

    def test_inactive_mapping_does_not_apply(self):
        self.user.groups.add(self.group)
        mapping = RoleMapping.objects.create(
            name='Inactive Contributors',
            group=self.group,
            role=RoleMapping.ROLE_CONTRIBUTOR,
            is_active=False,
        )

        self.assertFalse(mapping.applies_to_user(self.user))

    def test_external_mapping_is_configuration_only_until_provider_integration(self):
        mapping = RoleMapping.objects.create(
            name='External Security Admins',
            source=RoleMapping.SOURCE_EXTERNAL_GROUP,
            external_value='00000000-0000-0000-0000-000000000000',
            role=RoleMapping.ROLE_SECURITY_ADMIN,
        )

        self.assertFalse(mapping.applies_to_user(self.user))

    def test_string_representation_includes_role_and_scope(self):
        mapping = RoleMapping.objects.create(
            name='Payment Owners',
            group=self.group,
            role=RoleMapping.ROLE_BUSINESS_UNIT_OWNER,
            business_unit=self.business_unit,
        )

        self.assertEqual(str(mapping), 'Payment Owners (Business Unit Owner, Payments)')
