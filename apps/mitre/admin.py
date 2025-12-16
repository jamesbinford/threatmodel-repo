from django.contrib import admin
from .models import Tactic, Technique


@admin.register(Tactic)
class TacticAdmin(admin.ModelAdmin):
    list_display = ['tactic_id', 'name', 'framework']
    list_filter = ['framework']
    search_fields = ['tactic_id', 'name', 'description']
    ordering = ['tactic_id']


@admin.register(Technique)
class TechniqueAdmin(admin.ModelAdmin):
    list_display = ['technique_id', 'name', 'tactic', 'framework', 'parent']
    list_filter = ['framework', 'tactic']
    search_fields = ['technique_id', 'name', 'description']
    ordering = ['technique_id']
    raw_id_fields = ['parent']
