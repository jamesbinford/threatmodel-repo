def can_view_threat_model(user, threat_model):
    return user.is_authenticated


def can_create_threat_model(user, business_unit=None):
    return user.is_authenticated


def can_edit_threat_model(user, threat_model):
    if not user.is_authenticated:
        return False
    if user.is_staff or user.is_superuser:
        return True
    return threat_model.owner_id == user.id


def can_manage_finding(user, finding):
    return can_edit_threat_model(user, finding.threat_model)


def can_manage_diagram(user, diagram):
    return can_edit_threat_model(user, diagram.threat_model)
