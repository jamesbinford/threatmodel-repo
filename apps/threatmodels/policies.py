from apps.accounts.models import RoleMapping


def _business_unit_in_scope(business_unit, scope):
    if scope is None:
        return True
    if business_unit is None:
        return False
    return business_unit == scope or business_unit.is_descendant_of(scope, include_self=True)


def user_has_role(user, role, business_unit=None):
    if not user.is_authenticated:
        return False
    if role == RoleMapping.ROLE_SECURITY_ADMIN and (user.is_staff or user.is_superuser):
        return True

    mappings = RoleMapping.objects.filter(role=role, is_active=True).select_related('business_unit', 'group')
    for mapping in mappings:
        if _business_unit_in_scope(business_unit, mapping.business_unit) and mapping.applies_to_user(user):
            return True
    return False


def user_has_any_role(user, roles, business_unit=None):
    return any(user_has_role(user, role, business_unit) for role in roles)


def can_view_threat_model(user, threat_model):
    return user.is_authenticated


def can_create_threat_model(user, business_unit=None):
    if not user.is_authenticated:
        return False
    return user_has_any_role(user, [
        RoleMapping.ROLE_SECURITY_ADMIN,
        RoleMapping.ROLE_BUSINESS_UNIT_OWNER,
        RoleMapping.ROLE_CONTRIBUTOR,
    ], business_unit) or user.is_authenticated


def can_edit_threat_model(user, threat_model):
    if not user.is_authenticated:
        return False
    if user.is_staff or user.is_superuser:
        return True
    if user_has_any_role(user, [
        RoleMapping.ROLE_SECURITY_ADMIN,
        RoleMapping.ROLE_BUSINESS_UNIT_OWNER,
        RoleMapping.ROLE_CONTRIBUTOR,
    ], threat_model.business_unit):
        return True
    return threat_model.owner_id == user.id


def can_manage_finding(user, finding):
    return can_edit_threat_model(user, finding.threat_model)


def can_manage_diagram(user, diagram):
    return can_edit_threat_model(user, diagram.threat_model)
