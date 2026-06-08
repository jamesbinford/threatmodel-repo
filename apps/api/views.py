from django.db import transaction
from django.utils.text import slugify
from rest_framework import status
from rest_framework.response import Response
from rest_framework.exceptions import APIException, NotFound, PermissionDenied
from rest_framework.views import APIView

from apps.threatmodels.models import ThreatModel
from apps.threatmodels.policies import can_create_threat_model, can_edit_threat_model, can_view_threat_model
from .authentication import EntraJWTAuthentication
from .models import APISubmission
from .permissions import InternalAPIIsAuthenticated
from .serializers import (
    FindingBulkSubmissionResponseSerializer,
    FindingBulkSubmissionSerializer,
    ReferenceSerializer,
    ThreatModelReadSerializer,
    ThreatModelSubmissionResponseSerializer,
    ThreatModelSubmissionSerializer,
    upsert_finding,
)


class Conflict(APIException):
    status_code = status.HTTP_409_CONFLICT
    default_detail = 'Request conflicts with an existing resource.'
    default_code = 'conflict'


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


class InternalThreatModelSubmissionView(APIView):
    authentication_classes = [EntraJWTAuthentication]
    permission_classes = [InternalAPIIsAuthenticated]

    @transaction.atomic
    def post(self, request):
        serializer = ThreatModelSubmissionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        business_unit = data['business_unit']
        api_client = getattr(request, 'internal_api_client', None)
        if api_client and not api_client.business_unit_allowed(business_unit):
            raise PermissionDenied('API client is not scoped to this business unit.')

        external_id_provided = 'external_id' in data
        external_id = data.get('external_id') or None
        slug = data.get('slug') or slugify(data['title'])
        threat_model = ThreatModel.objects.filter(external_id=external_id).first() if external_id else None
        if threat_model is None:
            slug_match = ThreatModel.objects.filter(slug=slug).first()
            if slug_match and external_id and slug_match.external_id != external_id:
                raise Conflict('Slug is already used by another threat model.')
            threat_model = slug_match

        created = threat_model is None
        if created:
            if not can_create_threat_model(request.user, business_unit):
                raise PermissionDenied('You do not have permission to create threat models.')
            threat_model = ThreatModel(owner=request.user)
        elif not can_edit_threat_model(request.user, threat_model):
            raise PermissionDenied('You do not have permission to edit this threat model.')

        if external_id_provided:
            threat_model.external_id = external_id
        threat_model.source_system = data.get('source_system', threat_model.source_system)
        threat_model.title = data['title']
        threat_model.slug = slug
        threat_model.business_unit = business_unit
        threat_model.description = data['description']
        threat_model.status = data.get('status', threat_model.status or 'draft')
        threat_model.overall_risk = data.get('overall_risk', threat_model.overall_risk)
        threat_model.save()

        if 'tags' in data:
            threat_model.tags.set(data['tags'])

        finding_created_count = 0
        finding_updated_count = 0
        for finding_data in data.get('findings', []):
            _finding, finding_created = upsert_finding(threat_model, finding_data.copy())
            if finding_created:
                finding_created_count += 1
            else:
                finding_updated_count += 1

        APISubmission.record(request, status_code=status.HTTP_201_CREATED if created else status.HTTP_200_OK, threat_model=threat_model)
        response_serializer = ThreatModelSubmissionResponseSerializer({
            'id': threat_model.id,
            'external_id': threat_model.external_id,
            'slug': threat_model.slug,
            'url': threat_model.get_absolute_url(),
            'created': created,
            'finding_count': threat_model.findings.count(),
            'computed_risk': threat_model.computed_risk,
            'computed_risk_label': threat_model.computed_risk_label,
            'finding_created_count': finding_created_count,
            'finding_updated_count': finding_updated_count,
        })
        return Response(
            response_serializer.data,
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )


class InternalFindingSubmissionView(APIView):
    authentication_classes = [EntraJWTAuthentication]
    permission_classes = [InternalAPIIsAuthenticated]

    @transaction.atomic
    def post(self, request, slug):
        threat_model = ThreatModel.objects.filter(slug=slug).select_related('business_unit').first()
        if threat_model is None:
            raise NotFound('Threat model not found.')

        api_client = getattr(request, 'internal_api_client', None)
        if api_client and not api_client.business_unit_allowed(threat_model.business_unit):
            raise PermissionDenied('API client is not scoped to this business unit.')
        if not can_edit_threat_model(request.user, threat_model):
            raise PermissionDenied('You do not have permission to edit this threat model.')

        serializer = FindingBulkSubmissionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        created_count = 0
        updated_count = 0
        finding_summaries = []
        for finding_data in serializer.validated_data['findings']:
            finding, created = upsert_finding(threat_model, finding_data.copy())
            created_count += 1 if created else 0
            updated_count += 0 if created else 1
            finding_summaries.append({
                'external_id': finding.external_id,
                'threat_id': finding.threat_id,
                'status': finding.status,
            })

        APISubmission.record(request, status_code=status.HTTP_200_OK, threat_model=threat_model)
        response_serializer = FindingBulkSubmissionResponseSerializer({
            'threat_model': threat_model.slug,
            'created': created_count,
            'updated': updated_count,
            'findings': finding_summaries,
        })
        return Response(response_serializer.data)


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
