from django.db import models
from django.urls import reverse
from django.contrib.auth.models import User
from django.utils import timezone

from .upload_validation import is_previewable_image


class TechnologyTag(models.Model):
    """Technology tags for categorizing threat models by the technology being assessed."""
    name = models.CharField(max_length=100, unique=True)
    slug = models.SlugField(unique=True)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return self.name


class ThreatModel(models.Model):
    """A threat model document containing multiple findings."""
    RISK_CHOICES = [(i, str(i)) for i in range(1, 6)]  # 1-5 scale
    RISK_LABELS = {1: 'Very Low', 2: 'Low', 3: 'Medium', 4: 'High', 5: 'Critical'}
    STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('published', 'Published'),
        ('archived', 'Archived'),
    ]

    title = models.CharField(max_length=300)
    slug = models.SlugField(unique=True)
    external_id = models.CharField(max_length=300, unique=True, null=True, blank=True)
    source_system = models.CharField(max_length=100, blank=True)
    business_unit = models.ForeignKey(
        'organization.BusinessUnit',
        on_delete=models.PROTECT,
        related_name='threat_models'
    )
    description = models.TextField()
    overall_risk = models.IntegerField(choices=RISK_CHOICES, null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='draft')
    owner = models.ForeignKey(User, on_delete=models.PROTECT, related_name='owned_threat_models')
    tags = models.ManyToManyField(TechnologyTag, blank=True, related_name='threat_models')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-updated_at']

    def __str__(self):
        return self.title

    def get_absolute_url(self):
        return reverse('threatmodels:detail', kwargs={'slug': self.slug})

    @property
    def risk_label(self):
        return self.risk_label_for(self.overall_risk)

    @classmethod
    def risk_label_for(cls, risk):
        return cls.RISK_LABELS.get(risk, 'Not Set')

    @property
    def computed_risk(self):
        risks = [finding.effective_risk for finding in self.findings.all()]
        if not risks:
            return None
        return max(risks)

    @property
    def computed_risk_label(self):
        return self.risk_label_for(self.computed_risk)

    @property
    def has_risk_discrepancy(self):
        return (
            self.overall_risk is not None
            and self.computed_risk is not None
            and self.overall_risk != self.computed_risk
        )


class Diagram(models.Model):
    """Diagrams attached to a threat model."""
    DIAGRAM_TYPE_CHOICES = [
        ('architecture', 'Architecture Diagram'),
        ('threat_model', 'Threat Model Diagram'),
        ('other', 'Other'),
    ]

    threat_model = models.ForeignKey(
        ThreatModel,
        on_delete=models.CASCADE,
        related_name='diagrams'
    )
    title = models.CharField(max_length=200)
    diagram_type = models.CharField(max_length=20, choices=DIAGRAM_TYPE_CHOICES, default='other')
    file = models.FileField(upload_to='diagrams/')
    description = models.TextField(blank=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.title} ({self.threat_model.title})"

    @property
    def is_previewable_image(self):
        return is_previewable_image(self.file.name)


class Finding(models.Model):
    """Individual threat finding within a threat model."""
    STRIDE_CHOICES = [
        ('S', 'Spoofing'),
        ('T', 'Tampering'),
        ('R', 'Repudiation'),
        ('I', 'Information Disclosure'),
        ('D', 'Denial of Service'),
        ('E', 'Elevation of Privilege'),
    ]
    RISK_CHOICES = [(i, str(i)) for i in range(1, 6)]
    LIKELIHOOD_CHOICES = [
        ('almost_certain', 'Almost Certain'),
        ('likely', 'Likely'),
        ('possible', 'Possible'),
        ('unlikely', 'Unlikely'),
        ('rare', 'Rare'),
    ]
    STATUS_CHOICES = [
        ('open', 'Open'),
        ('in_progress', 'In Progress'),
        ('mitigated', 'Mitigated'),
        ('accepted', 'Accepted Risk'),
        ('closed', 'Closed'),
    ]

    threat_model = models.ForeignKey(
        ThreatModel,
        on_delete=models.CASCADE,
        related_name='findings'
    )
    threat_id = models.CharField(max_length=50)  # e.g., "TS-001-F01"
    external_id = models.CharField(max_length=300, blank=True)
    scenario = models.TextField()
    threat_object = models.CharField(max_length=300)
    mitre_technique = models.ForeignKey(
        'mitre.Technique',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='findings'
    )
    threat_catalog_rating = models.CharField(
        max_length=20,
        choices=LIKELIHOOD_CHOICES,
        blank=True
    )
    stride_category = models.CharField(max_length=1, choices=STRIDE_CHOICES)
    inherent_risk = models.IntegerField(choices=RISK_CHOICES)
    residual_risk = models.IntegerField(choices=RISK_CHOICES, null=True, blank=True)
    mitigations = models.TextField(blank=True)
    owner = models.CharField(max_length=200)
    owner_user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='assigned_findings'
    )
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='open')
    due_date = models.DateField(null=True, blank=True)
    resolution = models.TextField(blank=True)
    acceptance_reason = models.TextField(blank=True)
    verifier = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='findings_to_verify'
    )
    closed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['threat_id']
        constraints = [
            models.UniqueConstraint(
                fields=['threat_model', 'external_id'],
                condition=~models.Q(external_id=''),
                name='unique_finding_external_id_per_threat_model',
            ),
        ]

    def __str__(self):
        return f"{self.threat_id}: {self.threat_object}"

    def save(self, *args, **kwargs):
        if self.status == 'closed' and self.closed_at is None:
            self.closed_at = timezone.now()
        elif self.status != 'closed':
            self.closed_at = None
        super().save(*args, **kwargs)

    @property
    def inherent_risk_label(self):
        return ThreatModel.risk_label_for(self.inherent_risk)

    @property
    def residual_risk_label(self):
        return ThreatModel.risk_label_for(self.residual_risk)

    @property
    def effective_risk(self):
        if self.status == 'accepted':
            return self.residual_risk or self.inherent_risk
        if self.status in ['mitigated', 'closed'] and self.residual_risk is not None:
            return self.residual_risk
        if self.residual_risk is not None and self.mitigations.strip():
            return self.residual_risk
        return self.inherent_risk

    @property
    def effective_risk_label(self):
        return ThreatModel.risk_label_for(self.effective_risk)

    @property
    def is_open(self):
        return self.status in ['open', 'in_progress']

    @property
    def is_overdue(self):
        return self.is_open and self.due_date is not None and self.due_date < timezone.localdate()

    @property
    def workflow_owner(self):
        if self.owner_user:
            return self.owner_user.get_full_name() or self.owner_user.username
        return self.owner

    @property
    def stride_label(self):
        return dict(self.STRIDE_CHOICES).get(self.stride_category, '')


class Evidence(models.Model):
    """Evidence proving a threat is mitigated."""
    finding = models.ForeignKey(
        Finding,
        on_delete=models.CASCADE,
        related_name='evidence'
    )
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    file = models.FileField(upload_to='evidence/')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    uploaded_by = models.ForeignKey(User, on_delete=models.PROTECT)

    class Meta:
        verbose_name_plural = 'Evidence'

    def __str__(self):
        return f"{self.title} ({self.finding.threat_id})"
