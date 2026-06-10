import csv
import json
from collections import defaultdict
from io import StringIO

from django.shortcuts import render
from django.http import HttpResponse
from django.db.models import Avg
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_http_methods
from api.models import PromptLog


@ensure_csrf_cookie
def landing(request):
    return render(request, 'landing.html')


@ensure_csrf_cookie
def analyser(request):
    return render(request, 'analyser.html')


@ensure_csrf_cookie
def firewall(request):
    return render(request, 'firewall.html')


def dashboard(request):
    logs = PromptLog.objects.all()
    total = logs.count()
    blocked = logs.filter(decision='BLOCK').count()
    warned = logs.filter(decision='WARN').count()
    allowed = logs.filter(decision='ALLOW').count()
    forwarded = logs.filter(forwarded_to_llm=True).count()
    overrides = logs.filter(proceeded_after_warning=True).count()
    llm_errors = logs.filter(event_type=PromptLog.EVENT_LLM_ERROR).count()
    block_pct = round((blocked / total * 100) if total else 0)
    avg_score = logs.aggregate(avg=Avg('risk_score'))['avg'] or 0

    # --- Chart data: attack types breakdown ---
    attack_type_counts = {}
    for log in logs.exclude(attack_types=[]).values_list('attack_types', flat=True):
        if isinstance(log, list):
            for at in log:
                attack_type_counts[at] = attack_type_counts.get(at, 0) + 1

    # Sort by count descending, take top 8
    sorted_attacks = sorted(attack_type_counts.items(), key=lambda x: x[1], reverse=True)[:8]
    attack_labels = [a[0].replace('_', ' ').title() for a in sorted_attacks]
    attack_values = [a[1] for a in sorted_attacks]

    # --- Chart data: decisions over recent days ---
    daily = defaultdict(lambda: {'BLOCK': 0, 'WARN': 0, 'ALLOW': 0})
    for log in logs.values('created_at', 'decision'):
        day_key = log['created_at'].strftime('%b %d')
        daily[day_key][log['decision']] += 1

    daily_labels = list(daily.keys())[-14:]  # Last 14 days
    daily_block = [daily[d]['BLOCK'] for d in daily_labels]
    daily_warn = [daily[d]['WARN'] for d in daily_labels]
    daily_allow = [daily[d]['ALLOW'] for d in daily_labels]

    # --- Chart data: risk score distribution ---
    score_buckets = {'0-19': 0, '20-39': 0, '40-59': 0, '60-79': 0, '80-100': 0}
    for score in logs.values_list('risk_score', flat=True):
        if score < 20:
            score_buckets['0-19'] += 1
        elif score < 40:
            score_buckets['20-39'] += 1
        elif score < 60:
            score_buckets['40-59'] += 1
        elif score < 80:
            score_buckets['60-79'] += 1
        else:
            score_buckets['80-100'] += 1

    context = {
        'total': total,
        'blocked': blocked,
        'warned': warned,
        'allowed': allowed,
        'forwarded': forwarded,
        'overrides': overrides,
        'llm_errors': llm_errors,
        'block_pct': block_pct,
        'avg_score': round(avg_score, 1),
        'recent': logs[:20],
        # Chart data (serialized to JSON for Chart.js)
        'chart_decisions': json.dumps([allowed, warned, blocked]),
        'chart_attack_labels': json.dumps(attack_labels),
        'chart_attack_values': json.dumps(attack_values),
        'chart_daily_labels': json.dumps(daily_labels),
        'chart_daily_block': json.dumps(daily_block),
        'chart_daily_warn': json.dumps(daily_warn),
        'chart_daily_allow': json.dumps(daily_allow),
        'chart_score_labels': json.dumps(list(score_buckets.keys())),
        'chart_score_values': json.dumps(list(score_buckets.values())),
    }
    return render(request, 'dashboard.html', context)


@require_http_methods(["GET"])
def export_logs(request):
    """Export audit logs as CSV or JSON."""
    fmt = request.GET.get('format', 'csv').lower()
    decision_filter = request.GET.get('decision', '').upper()
    event_filter = request.GET.get('event', '').upper()

    logs = PromptLog.objects.all()
    if decision_filter in ('ALLOW', 'WARN', 'BLOCK'):
        logs = logs.filter(decision=decision_filter)
    if event_filter in ('ANALYZE', 'FIREWALL', 'LLM_FORWARD', 'LLM_ERROR'):
        logs = logs.filter(event_type=event_filter)

    fields = [
        'request_id', 'event_type', 'decision', 'risk_score', 'threat_level',
        'attack_types', 'reasons', 'ai_reasoning', 'prompt', 'prompt_length',
        'llm_used', 'forwarded_to_llm', 'proceeded_after_warning',
        'client_ip', 'processing_time_ms', 'created_at',
    ]

    if fmt == 'json':
        data = []
        for log in logs.values(*fields):
            log['created_at'] = log['created_at'].isoformat() if log.get('created_at') else None
            data.append(log)
        response = HttpResponse(
            json.dumps(data, indent=2, default=str),
            content_type='application/json',
        )
        response['Content-Disposition'] = 'attachment; filename="promptguard_audit_logs.json"'
        return response

    # CSV export (default)
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    for log in logs.values(*fields):
        log['created_at'] = log['created_at'].isoformat() if log.get('created_at') else ''
        log['attack_types'] = ', '.join(log.get('attack_types') or [])
        log['reasons'] = ' | '.join(log.get('reasons') or [])
        writer.writerow(log)

    response = HttpResponse(output.getvalue(), content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="promptguard_audit_logs.csv"'
    return response
