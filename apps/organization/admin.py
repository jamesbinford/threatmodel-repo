from django.contrib import admin
from mptt.admin import MPTTModelAdmin
from .models import BusinessUnit


@admin.register(BusinessUnit)
class BusinessUnitAdmin(MPTTModelAdmin):
    list_display = ['name', 'slug', 'parent', 'created_at']
    list_filter = ['created_at']
    search_fields = ['name', 'description']
    prepopulated_fields = {'slug': ('name',)}
    mptt_level_indent = 20
