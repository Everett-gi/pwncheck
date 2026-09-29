"""Rotas de administração (fase 5): só para usuários com is_admin.

Um usuário vira administrador por um comando no servidor — nunca pela API:
    python -m app.manage make-admin email@exemplo.com
"""

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Query

from app import metrics
from app.deps import AdminUser, DbSession
from app.schemas import DailyMetrics, ErrorResponse, MetricsResponse

router = APIRouter(prefix="/admin", tags=["administração"])


@router.get(
    "/metrics",
    response_model=MetricsResponse,
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}},
)
def usage_metrics(
    session: DbSession,
    admin: AdminUser,
    days: Annotated[int, Query(ge=1, le=90, description="Quantos dias para trás.")] = 7,
) -> MetricsResponse:
    """Uso da API por dia: verificações, vazamentos encontrados, eficiência do cache,
    cadastros e requisições barradas pelo rate limit. Só números agregados."""
    rows = metrics.daily_report(session, today=datetime.now(UTC).date(), days=days)
    totals = {name: sum(getattr(row, name) for row in rows) for name in metrics.COUNTERS}
    lookups = totals["cache_hits"] + totals["cache_misses"] + totals["cache_stale"]
    return MetricsResponse(
        days=[DailyMetrics.model_validate(row) for row in rows],
        totals=totals,
        cache_hit_rate=round(totals["cache_hits"] / lookups, 4) if lookups else None,
    )
