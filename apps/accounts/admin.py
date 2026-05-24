from django.contrib import admin
from .models import RoleMapping


@admin.register(RoleMapping)
class RoleMappingAdmin(admin.ModelAdmin):
    list_display = ['name', 'role', 'source', 'group', 'business_unit', 'is_active']
    list_filter = ['role', 'source', 'is_active', 'business_unit']
    search_fields = ['name', 'external_value', 'claim_name', 'group__name']
    raw_id_fields = ['business_unit']
