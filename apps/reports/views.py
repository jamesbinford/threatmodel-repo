from django.views.generic import TemplateView, View
from django.http import HttpResponse
from django.db.models import Count, Avg
from django.db.models.functions import TruncMonth
from django.template.loader import render_to_string
from django.utils import timezone
from datetime import timedelta
from collections import defaultdict
from apps.threatmodels.models import ThreatModel, Finding, TechnologyTag
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

        # Trend data: Findings by business unit over last 12 months
        twelve_months_ago = timezone.now() - timedelta(days=365)

        # Get findings grouped by month and top-level business unit
        trend_data = Finding.objects.filter(
            created_at__gte=twelve_months_ago
        ).annotate(
            month=TruncMonth('created_at')
        ).values(
            'month',
            'threat_model__business_unit__name',
            'threat_model__business_unit__parent__name'
        ).annotate(
            count=Count('id')
        ).order_by('month')

        # Process trend data into chart format
        # Group by top-level business unit (or self if no parent)
        months_set = set()
        bu_data = defaultdict(lambda: defaultdict(int))

        for item in trend_data:
            month_str = item['month'].strftime('%Y-%m') if item['month'] else 'Unknown'
            months_set.add(month_str)
            # Use parent name if exists, otherwise use the BU name
            bu_name = item['threat_model__business_unit__parent__name'] or item['threat_model__business_unit__name']
            if bu_name:
                bu_data[bu_name][month_str] += item['count']

        # Sort months chronologically
        sorted_months = sorted(months_set)

        # Build datasets for Chart.js
        trend_labels = sorted_months
        trend_datasets = []
        colors = [
            '#0d6efd', '#198754', '#dc3545', '#ffc107', '#0dcaf0',
            '#6f42c1', '#fd7e14', '#20c997', '#6c757d', '#d63384'
        ]

        for idx, (bu_name, month_counts) in enumerate(sorted(bu_data.items())):
            dataset = {
                'label': bu_name,
                'data': [month_counts.get(m, 0) for m in sorted_months],
                'borderColor': colors[idx % len(colors)],
                'backgroundColor': colors[idx % len(colors)] + '20',
                'fill': False,
                'tension': 0.1
            }
            trend_datasets.append(dataset)

        context['trend_labels_json'] = json.dumps(trend_labels)
        context['trend_datasets_json'] = json.dumps(trend_datasets)

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


class TagFrequencyReportView(TemplateView):
    """Report showing technology tag frequency over configurable time periods."""
    template_name = 'reports/tag_frequency.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Get period from query parameter (default 30 days)
        period = self.request.GET.get('period', '30')
        try:
            days = int(period)
            if days not in [30, 60, 90, 365]:
                days = 30
        except ValueError:
            days = 30

        cutoff_date = timezone.now() - timedelta(days=days)

        # Get tag frequency for threat models created in the period
        tag_frequency = TechnologyTag.objects.filter(
            threat_models__created_at__gte=cutoff_date
        ).annotate(
            count=Count('threat_models', distinct=True)
        ).order_by('-count')

        # Summary stats
        total_tags = TechnologyTag.objects.count()
        tags_used_in_period = tag_frequency.filter(count__gt=0).count()
        threat_models_in_period = ThreatModel.objects.filter(
            created_at__gte=cutoff_date
        ).count()
        tagged_threat_models = ThreatModel.objects.filter(
            created_at__gte=cutoff_date,
            tags__isnull=False
        ).distinct().count()

        context['period'] = days
        context['cutoff_date'] = cutoff_date
        context['tag_frequency'] = tag_frequency
        context['total_tags'] = total_tags
        context['tags_used_in_period'] = tags_used_in_period
        context['threat_models_in_period'] = threat_models_in_period
        context['tagged_threat_models'] = tagged_threat_models

        # Chart data (top 15 tags)
        top_tags = list(tag_frequency[:15])
        chart_labels = [t.name for t in top_tags]
        chart_data = [t.count for t in top_tags]
        context['chart_labels_json'] = json.dumps(chart_labels)
        context['chart_data_json'] = json.dumps(chart_data)

        return context
