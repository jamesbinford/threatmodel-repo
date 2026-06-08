from rest_framework import serializers

from apps.mitre.models import Technique
from apps.organization.models import BusinessUnit
from apps.threatmodels.models import Finding, TechnologyTag, ThreatModel


class InternalAPIStatusSerializer(serializers.Serializer):
    status = serializers.CharField()
    version = serializers.CharField()


class FindingReadSerializer(serializers.ModelSerializer):
    mitre_technique = serializers.CharField(source='mitre_technique.technique_id', allow_null=True)
    owner_user = serializers.CharField(source='owner_user.username', allow_null=True)
    verifier = serializers.CharField(source='verifier.username', allow_null=True)
    effective_risk = serializers.IntegerField()
    effective_risk_label = serializers.CharField()
    is_overdue = serializers.BooleanField()

    class Meta:
        model = Finding
        fields = [
            'external_id', 'threat_id', 'scenario', 'threat_object',
            'mitre_technique', 'threat_catalog_rating', 'stride_category',
            'inherent_risk', 'residual_risk', 'effective_risk',
            'effective_risk_label', 'mitigations', 'owner', 'owner_user',
            'status', 'due_date', 'resolution', 'acceptance_reason',
            'verifier', 'closed_at', 'is_overdue',
        ]


class ThreatModelReadSerializer(serializers.ModelSerializer):
    business_unit = serializers.CharField(source='business_unit.slug')
    owner = serializers.CharField(source='owner.username')
    tags = serializers.SerializerMethodField()
    findings = FindingReadSerializer(many=True)
    computed_risk = serializers.IntegerField(allow_null=True)
    computed_risk_label = serializers.CharField()
    html_url = serializers.SerializerMethodField()

    class Meta:
        model = ThreatModel
        fields = [
            'id', 'external_id', 'source_system', 'title', 'slug',
            'business_unit', 'description', 'status', 'overall_risk',
            'computed_risk', 'computed_risk_label', 'owner', 'tags',
            'findings', 'html_url', 'created_at', 'updated_at',
        ]

    def get_tags(self, threat_model):
        return [tag.name for tag in threat_model.tags.all()]

    def get_html_url(self, threat_model):
        request = self.context.get('request')
        url = threat_model.get_absolute_url()
        return request.build_absolute_uri(url) if request else url


class ReferenceSerializer(serializers.Serializer):
    risk = serializers.SerializerMethodField()
    threat_model_statuses = serializers.SerializerMethodField()
    finding_statuses = serializers.SerializerMethodField()
    stride_categories = serializers.SerializerMethodField()
    business_units = serializers.SerializerMethodField()
    tags = serializers.SerializerMethodField()
    mitre_techniques = serializers.SerializerMethodField()

    def get_risk(self, _obj):
        return [
            {'value': value, 'label': ThreatModel.risk_label_for(value)}
            for value, _label in ThreatModel.RISK_CHOICES
        ]

    def get_threat_model_statuses(self, _obj):
        return [value for value, _label in ThreatModel.STATUS_CHOICES]

    def get_finding_statuses(self, _obj):
        return [value for value, _label in Finding.STATUS_CHOICES]

    def get_stride_categories(self, _obj):
        return [value for value, _label in Finding.STRIDE_CHOICES]

    def get_business_units(self, _obj):
        client = self.context.get('api_client')
        queryset = BusinessUnit.objects.all()
        if client and client.business_unit_scope:
            queryset = queryset.filter(
                tree_id=client.business_unit_scope.tree_id,
                lft__gte=client.business_unit_scope.lft,
                rght__lte=client.business_unit_scope.rght,
            )
        return [{'slug': bu.slug, 'name': bu.name} for bu in queryset]

    def get_tags(self, _obj):
        return list(TechnologyTag.objects.values_list('name', flat=True))

    def get_mitre_techniques(self, _obj):
        return [
            {
                'technique_id': technique.technique_id,
                'name': technique.name,
                'framework': technique.framework,
            }
            for technique in Technique.objects.all()
        ]
