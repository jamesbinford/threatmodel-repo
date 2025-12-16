from django.views.generic import TemplateView, View
from django.http import HttpResponse
from django.db.models import Count, Avg
from django.template.loader import render_to_string
from apps.threatmodels.models import ThreatModel, Finding
from apps.organization.models import BusinessUnit
from apps.mitre.models import Technique
import json


class DashboardView(TemplateView):
    template_name = 'reports/dashboard.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Overall stats
        context['total_threat_models'] = ThreatModel.objects.count()
        context['total_findings'] = Finding.objects.count()
        context['published_count'] = ThreatModel.objects.filter(status='published').count()

        # Risk distribution
        risk_distribution = ThreatModel.objects.filter(
            overall_risk__isnull=False
        ).values('overall_risk').annotate(
            count=Count('id')
        ).order_by('overall_risk')
        context['risk_distribution'] = list(risk_distribution)
        context['risk_distribution_json'] = json.dumps(list(risk_distribution))

        # Risk by business unit
        bu_risk = BusinessUnit.objects.annotate(
            threat_model_count=Count('threat_models'),
            avg_risk=Avg('threat_models__overall_risk')
        ).filter(threat_model_count__gt=0).values('name', 'threat_model_count', 'avg_risk')
        context['bu_risk'] = list(bu_risk)
        context['bu_risk_json'] = json.dumps(list(bu_risk))

        # STRIDE distribution
        stride_distribution = Finding.objects.values('stride_category').annotate(
            count=Count('id')
        ).order_by('stride_category')
        context['stride_distribution'] = list(stride_distribution)
        context['stride_distribution_json'] = json.dumps(list(stride_distribution))

        # Top MITRE techniques
        top_techniques = Technique.objects.annotate(
            finding_count=Count('findings')
        ).filter(finding_count__gt=0).order_by('-finding_count')[:10]
        context['top_techniques'] = top_techniques

        # High risk findings (inherent risk 4 or 5) without mitigation
        context['high_risk_findings'] = Finding.objects.filter(
            inherent_risk__gte=4,
            residual_risk__isnull=True
        ).select_related('threat_model')[:10]

        return context


class DashboardPDFView(View):
    def get(self, request):
        try:
            from weasyprint import HTML
        except ImportError:
            return HttpResponse(
                "WeasyPrint is not installed. Install it with: pip install weasyprint",
                status=500
            )

        # Get the same context as the dashboard
        dashboard_view = DashboardView()
        dashboard_view.request = request
        context = dashboard_view.get_context_data()

        # Render PDF template
        html_string = render_to_string('reports/dashboard_pdf.html', context)

        # Generate PDF
        html = HTML(string=html_string, base_url=request.build_absolute_uri('/'))
        pdf = html.write_pdf()

        response = HttpResponse(pdf, content_type='application/pdf')
        response['Content-Disposition'] = 'attachment; filename="threat-model-dashboard.pdf"'
        return response
