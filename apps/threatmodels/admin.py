from django.contrib import admin
from .models import ThreatModel, Diagram, Finding, Evidence


class DiagramInline(admin.TabularInline):
    model = Diagram
    extra = 0


class FindingInline(admin.TabularInline):
    model = Finding
    extra = 0
    fields = ['threat_id', 'threat_object', 'stride_category', 'inherent_risk', 'residual_risk', 'owner']
    readonly_fields = ['threat_id']


class EvidenceInline(admin.TabularInline):
    model = Evidence
    extra = 0


@admin.register(ThreatModel)
class ThreatModelAdmin(admin.ModelAdmin):
    list_display = ['title', 'business_unit', 'status', 'overall_risk', 'owner', 'updated_at']
    list_filter = ['status', 'overall_risk', 'business_unit', 'created_at']
    search_fields = ['title', 'description']
    prepopulated_fields = {'slug': ('title',)}
    raw_id_fields = ['owner']
    date_hierarchy = 'created_at'
    inlines = [DiagramInline, FindingInline]


@admin.register(Diagram)
class DiagramAdmin(admin.ModelAdmin):
    list_display = ['title', 'threat_model', 'uploaded_at']
    list_filter = ['uploaded_at']
    search_fields = ['title', 'description']
    raw_id_fields = ['threat_model']


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = ['threat_id', 'threat_object', 'threat_model', 'stride_category', 'inherent_risk', 'residual_risk']
    list_filter = ['stride_category', 'inherent_risk', 'residual_risk', 'threat_catalog_rating']
    search_fields = ['threat_id', 'scenario', 'threat_object', 'mitigations']
    raw_id_fields = ['threat_model', 'mitre_technique']
    inlines = [EvidenceInline]


@admin.register(Evidence)
class EvidenceAdmin(admin.ModelAdmin):
    list_display = ['title', 'finding', 'uploaded_at', 'uploaded_by']
    list_filter = ['uploaded_at']
    search_fields = ['title', 'description']
    raw_id_fields = ['finding', 'uploaded_by']
