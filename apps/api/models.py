from django.conf import settings
from django.db import models
from django.utils import timezone


class InternalAPIClient(models.Model):
    """Maps an Entra workload identity to a local service user."""

    name = models.CharField(max_length=200)
    entra_app_id = models.CharField(max_length=100, unique=True)
    entra_object_id = models.CharField(max_length=100, unique=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name='internal_api_clients')
    business_unit_scope = models.ForeignKey(
        'organization.BusinessUnit',
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name='internal_api_clients',
    )
    is_active = models.BooleanField(default=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return self.name

    @property
    def is_expired(self):
        return self.expires_at is not None and self.expires_at <= timezone.now()

    @property
    def is_usable(self):
        return self.is_active and not self.is_expired

    def mark_used(self):
        self.last_used_at = timezone.now()
        self.save(update_fields=['last_used_at'])

    def business_unit_allowed(self, business_unit):
        if self.business_unit_scope is None:
            return True
        if business_unit is None:
            return False
        return (
            business_unit == self.business_unit_scope
            or business_unit.is_descendant_of(self.business_unit_scope, include_self=True)
        )

    @classmethod
    def active_for_claims(cls, *, app_id=None, object_id=None):
        queryset = cls.objects.select_related('user', 'business_unit_scope')
        if object_id:
            queryset = queryset.filter(entra_object_id=object_id)
        elif app_id:
            queryset = queryset.filter(entra_app_id=app_id)
        else:
            return None

        client = queryset.first()
        return client if client and client.is_usable else None


class APISubmission(models.Model):
    """Stores internal API submission metadata without sensitive payloads."""

    request_id = models.CharField(max_length=100, blank=True)
    idempotency_key = models.CharField(max_length=200, blank=True)
    endpoint = models.CharField(max_length=300)
    method = models.CharField(max_length=10)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    api_client = models.ForeignKey(InternalAPIClient, on_delete=models.SET_NULL, null=True, blank=True)
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    status_code = models.PositiveSmallIntegerField(null=True, blank=True)
    threat_model = models.ForeignKey(
        'threatmodels.ThreatModel',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='api_submissions',
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.method} {self.endpoint} ({self.status_code or "pending"})'

    @classmethod
    def record(cls, request, *, status_code=None, threat_model=None):
        return cls.objects.create(
            request_id=request.headers.get('X-Request-ID', ''),
            idempotency_key=request.headers.get('Idempotency-Key', ''),
            endpoint=request.path,
            method=request.method,
            user=request.user if getattr(request, 'user', None) and request.user.is_authenticated else None,
            api_client=getattr(request, 'internal_api_client', None),
            source_ip=client_ip(request),
            status_code=status_code,
            threat_model=threat_model,
        )


def client_ip(request):
    forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if forwarded_for:
        return forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')
