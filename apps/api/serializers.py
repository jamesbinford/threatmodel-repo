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


class FindingSubmissionSerializer(serializers.Serializer):
    external_id = serializers.CharField(required=False, allow_blank=True, max_length=300)
    threat_id = serializers.CharField(max_length=50)
    scenario = serializers.CharField()
    threat_object = serializers.CharField(max_length=300)
    mitre_technique = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    threat_catalog_rating = serializers.ChoiceField(
        choices=Finding.LIKELIHOOD_CHOICES,
        required=False,
        allow_blank=True,
    )
    stride_category = serializers.ChoiceField(choices=Finding.STRIDE_CHOICES)
    inherent_risk = serializers.ChoiceField(choices=Finding.RISK_CHOICES)
    residual_risk = serializers.ChoiceField(choices=Finding.RISK_CHOICES, required=False, allow_null=True)
    mitigations = serializers.CharField(required=False, allow_blank=True)
    owner = serializers.CharField(max_length=200)
    status = serializers.ChoiceField(choices=Finding.STATUS_CHOICES, required=False)
    due_date = serializers.DateField(required=False, allow_null=True)
    resolution = serializers.CharField(required=False, allow_blank=True)
    acceptance_reason = serializers.CharField(required=False, allow_blank=True)

    def validate_mitre_technique(self, value):
        if not value:
            return None
        technique = Technique.objects.filter(technique_id=value).first()
        if technique is None:
            raise serializers.ValidationError(f'Unknown MITRE technique ID: {value}')
        return technique


class ThreatModelSubmissionSerializer(serializers.Serializer):
    external_id = serializers.CharField(required=False, allow_blank=True, allow_null=True, max_length=300)
    source_system = serializers.CharField(required=False, allow_blank=True, max_length=100)
    title = serializers.CharField(max_length=300)
    slug = serializers.SlugField(required=False, allow_blank=True)
    business_unit = serializers.CharField()
    description = serializers.CharField()
    status = serializers.ChoiceField(choices=ThreatModel.STATUS_CHOICES, required=False)
    overall_risk = serializers.ChoiceField(choices=ThreatModel.RISK_CHOICES, required=False, allow_null=True)
    tags = serializers.ListField(child=serializers.CharField(), required=False)
    findings = FindingSubmissionSerializer(many=True, required=False)

    def validate_business_unit(self, value):
        business_unit = BusinessUnit.objects.filter(slug=value).first()
        if business_unit is None:
            raise serializers.ValidationError(f'Unknown business unit slug: {value}')
        return business_unit

    def validate_tags(self, values):
        tags = []
        missing = []
        for value in values:
            tag = TechnologyTag.objects.filter(name=value).first()
            if tag:
                tags.append(tag)
            else:
                missing.append(value)
        if missing:
            raise serializers.ValidationError([f'Unknown technology tag: {value}' for value in missing])
        return tags


class ThreatModelSubmissionResponseSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    external_id = serializers.CharField(allow_null=True)
    slug = serializers.CharField()
    url = serializers.CharField()
    created = serializers.BooleanField()
    finding_count = serializers.IntegerField()
    computed_risk = serializers.IntegerField(allow_null=True)
    computed_risk_label = serializers.CharField()


def upsert_finding(threat_model, finding_data):
    external_id = finding_data.get('external_id', '')
    lookup = {'threat_model': threat_model, 'external_id': external_id} if external_id else None
    finding = Finding.objects.filter(**lookup).first() if lookup else None
    created = finding is None
    if finding is None:
        finding = Finding(threat_model=threat_model)

    mitre_technique = finding_data.pop('mitre_technique', None)
    for field, value in finding_data.items():
        setattr(finding, field, value)
    finding.mitre_technique = mitre_technique
    if not finding.status:
        finding.status = 'open'
    finding.save()
    return finding, created
