from django.contrib import admin

from .models import APISubmission, InternalAPIClient


@admin.register(InternalAPIClient)
class InternalAPIClientAdmin(admin.ModelAdmin):
    list_display = ['name', 'entra_app_id', 'entra_object_id', 'user', 'business_unit_scope', 'is_active', 'expires_at', 'last_used_at']
    list_filter = ['is_active', 'business_unit_scope', 'expires_at', 'last_used_at']
    search_fields = ['name', 'entra_app_id', 'entra_object_id', 'user__username', 'user__email']
    raw_id_fields = ['user', 'business_unit_scope']
    readonly_fields = ['last_used_at', 'created_at', 'updated_at']


@admin.register(APISubmission)
class APISubmissionAdmin(admin.ModelAdmin):
    list_display = ['created_at', 'method', 'endpoint', 'status_code', 'user', 'api_client', 'threat_model']
    list_filter = ['method', 'status_code', 'created_at']
    search_fields = ['request_id', 'idempotency_key', 'endpoint', 'user__username', 'api_client__name']
    raw_id_fields = ['user', 'api_client', 'threat_model']
    readonly_fields = [
        'request_id', 'idempotency_key', 'endpoint', 'method', 'user',
        'api_client', 'source_ip', 'status_code', 'threat_model', 'created_at',
    ]
