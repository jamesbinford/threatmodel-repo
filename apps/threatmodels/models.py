from django.db import models
from django.urls import reverse
from django.contrib.auth.models import User


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
    STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('published', 'Published'),
        ('archived', 'Archived'),
    ]

    title = models.CharField(max_length=300)
    slug = models.SlugField(unique=True)
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
        labels = {1: 'Very Low', 2: 'Low', 3: 'Medium', 4: 'High', 5: 'Critical'}
        return labels.get(self.overall_risk, 'Not Set')


class Diagram(models.Model):
    """Diagrams attached to a threat model."""
    threat_model = models.ForeignKey(
        ThreatModel,
        on_delete=models.CASCADE,
        related_name='diagrams'
    )
    title = models.CharField(max_length=200)
    file = models.FileField(upload_to='diagrams/')
    description = models.TextField(blank=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.title} ({self.threat_model.title})"


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

    threat_model = models.ForeignKey(
        ThreatModel,
        on_delete=models.CASCADE,
        related_name='findings'
    )
    threat_id = models.CharField(max_length=50)  # e.g., "TM-001-F01"
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
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['threat_id']

    def __str__(self):
        return f"{self.threat_id}: {self.threat_object}"

    @property
    def inherent_risk_label(self):
        labels = {1: 'Very Low', 2: 'Low', 3: 'Medium', 4: 'High', 5: 'Critical'}
        return labels.get(self.inherent_risk, 'Not Set')

    @property
    def residual_risk_label(self):
        labels = {1: 'Very Low', 2: 'Low', 3: 'Medium', 4: 'High', 5: 'Critical'}
        return labels.get(self.residual_risk, 'Not Set')

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
