from rest_framework.response import Response
from rest_framework.exceptions import NotFound, PermissionDenied
from rest_framework.views import APIView

from apps.threatmodels.models import ThreatModel
from apps.threatmodels.policies import can_view_threat_model
from .authentication import EntraJWTAuthentication
from .permissions import InternalAPIIsAuthenticated
from .serializers import ReferenceSerializer, ThreatModelReadSerializer


class InternalAPIStatusView(APIView):
    authentication_classes = [EntraJWTAuthentication]
    permission_classes = [InternalAPIIsAuthenticated]

    def get(self, request):
        return Response({'status': 'ok', 'version': 'v1'})


class InternalReferenceView(APIView):
    authentication_classes = [EntraJWTAuthentication]
    permission_classes = [InternalAPIIsAuthenticated]

    def get(self, request):
        serializer = ReferenceSerializer(
            {},
            context={'api_client': getattr(request, 'internal_api_client', None)},
        )
        return Response(serializer.data)


class InternalThreatModelDetailView(APIView):
    authentication_classes = [EntraJWTAuthentication]
    permission_classes = [InternalAPIIsAuthenticated]

    def get(self, request, slug):
        threat_model = ThreatModel.objects.filter(slug=slug).select_related(
            'business_unit', 'owner'
        ).prefetch_related(
            'tags',
            'findings__mitre_technique',
            'findings__owner_user',
            'findings__verifier',
        ).first()
        if threat_model is None:
            raise NotFound('Threat model not found.')

        api_client = getattr(request, 'internal_api_client', None)
        if api_client and not api_client.business_unit_allowed(threat_model.business_unit):
            raise PermissionDenied('API client is not scoped to this business unit.')
        if not can_view_threat_model(request.user, threat_model):
            raise PermissionDenied('You do not have permission to view this threat model.')

        serializer = ThreatModelReadSerializer(threat_model, context={'request': request})
        return Response(serializer.data)
