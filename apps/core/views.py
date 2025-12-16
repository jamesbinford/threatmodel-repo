from django.views.generic import TemplateView
from apps.threatmodels.models import ThreatModel
from apps.organization.models import BusinessUnit


class HomeView(TemplateView):
    template_name = 'core/home.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['recent_threat_models'] = ThreatModel.objects.select_related(
            'business_unit', 'owner'
        ).order_by('-updated_at')[:5]
        context['business_units'] = BusinessUnit.objects.filter(parent__isnull=True)
        context['total_threat_models'] = ThreatModel.objects.count()
        context['published_count'] = ThreatModel.objects.filter(status='published').count()
        context['draft_count'] = ThreatModel.objects.filter(status='draft').count()
        return context
