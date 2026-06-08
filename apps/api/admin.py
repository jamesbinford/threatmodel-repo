from django.contrib import admin

from .models import InternalAPIClient


@admin.register(InternalAPIClient)
class InternalAPIClientAdmin(admin.ModelAdmin):
    list_display = ['name', 'entra_app_id', 'entra_object_id', 'user', 'business_unit_scope', 'is_active', 'expires_at', 'last_used_at']
    list_filter = ['is_active', 'business_unit_scope', 'expires_at', 'last_used_at']
    search_fields = ['name', 'entra_app_id', 'entra_object_id', 'user__username', 'user__email']
    raw_id_fields = ['user', 'business_unit_scope']
    readonly_fields = ['last_used_at', 'created_at', 'updated_at']
