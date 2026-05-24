from django.db import models
from django.contrib.auth.models import Group


class RoleMapping(models.Model):
    """Maps local or external identity groups/claims to product roles."""

    ROLE_VIEWER = 'viewer'
    ROLE_CONTRIBUTOR = 'contributor'
    ROLE_BUSINESS_UNIT_OWNER = 'business_unit_owner'
    ROLE_SECURITY_ADMIN = 'security_admin'

    ROLE_CHOICES = [
        (ROLE_VIEWER, 'Viewer'),
        (ROLE_CONTRIBUTOR, 'Contributor'),
        (ROLE_BUSINESS_UNIT_OWNER, 'Business Unit Owner'),
        (ROLE_SECURITY_ADMIN, 'Security Admin'),
    ]

    SOURCE_DJANGO_GROUP = 'django_group'
    SOURCE_EXTERNAL_GROUP = 'external_group'
    SOURCE_CLAIM = 'claim'

    SOURCE_CHOICES = [
        (SOURCE_DJANGO_GROUP, 'Django Group'),
        (SOURCE_EXTERNAL_GROUP, 'External Group'),
        (SOURCE_CLAIM, 'Claim'),
    ]

    name = models.CharField(max_length=200)
    source = models.CharField(max_length=30, choices=SOURCE_CHOICES, default=SOURCE_DJANGO_GROUP)
    group = models.ForeignKey(Group, on_delete=models.CASCADE, null=True, blank=True)
    external_value = models.CharField(
        max_length=300,
        blank=True,
        help_text='External group ID or claim value from AD/Entra/OIDC/SAML.',
    )
    claim_name = models.CharField(max_length=200, blank=True)
    role = models.CharField(max_length=40, choices=ROLE_CHOICES)
    business_unit = models.ForeignKey(
        'organization.BusinessUnit',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='role_mappings',
    )
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        scope = self.business_unit.name if self.business_unit else 'Global'
        return f'{self.name} ({self.get_role_display()}, {scope})'

    def applies_to_user(self, user):
        if not user.is_authenticated or not self.is_active:
            return False
        if self.source == self.SOURCE_DJANGO_GROUP and self.group_id:
            return user.groups.filter(pk=self.group_id).exists()
        return False
