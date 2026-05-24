from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404

from .models import ThreatModel
from .policies import can_edit_threat_model


class ThreatModelEditRequiredMixin:
    permission_denied_message = 'You do not have permission to edit this threat model.'

    def get_permission_threat_model(self):
        if hasattr(self, 'object') and self.object is not None:
            if isinstance(self.object, ThreatModel):
                return self.object
            return self.object.threat_model

        if self.kwargs.get('pk') is not None and hasattr(self, 'get_object'):
            self.object = self.get_object()
            return self.object.threat_model

        if getattr(self, 'model', None) is ThreatModel and hasattr(self, 'get_object'):
            self.object = self.get_object()
            return self.object

        if hasattr(self, 'threat_model'):
            return self.threat_model

        slug = self.kwargs.get('slug')
        return get_object_or_404(ThreatModel, slug=slug)

    def dispatch(self, request, *args, **kwargs):
        threat_model = self.get_permission_threat_model()
        if not can_edit_threat_model(request.user, threat_model):
            raise PermissionDenied(self.permission_denied_message)
        self.threat_model = threat_model
        return super().dispatch(request, *args, **kwargs)
