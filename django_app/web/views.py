from django.shortcuts import render
from django.db.models import Avg
from django.views.decorators.csrf import ensure_csrf_cookie
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
    }
    return render(request, 'dashboard.html', context)
