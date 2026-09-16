# app/api/pluggy_routes.py (ou app/integracoes/api/pluggy_routes.py)
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from app.api.deps import get_current_user, require_admin
from app.identidade.persistence.pessoa_orm import PessoaORM
from app.core.settings import settings

router = APIRouter(prefix="/api/v1/pluggy", tags=["pluggy"])


def get_pluggy(request: Request):
    if not settings.pluggy_enabled:
        raise HTTPException(503, "Integração Pluggy desabilitada neste ambiente")
    client = getattr(request.app.state, "pluggy_client", None)
    if not client:
        raise HTTPException(500, "Pluggy client not initialized")
    return client


@router.get("/connect-token")
async def get_connect_token(
    _: PessoaORM = Depends(get_current_user),
    client=Depends(get_pluggy),
) -> dict[str, str]:
    try:
        token = await client.create_connect_token()
        return {"connectToken": token}
    except Exception as e:  # pragma: no cover (erro externo da Pluggy)
        raise HTTPException(status_code=502, detail=f"Connect token error: {e}")


@router.get("/accounts/{item_id}")
async def accounts(
    item_id: str,
    _: PessoaORM = Depends(get_current_user),
    client=Depends(get_pluggy),
) -> list[dict[str, Any]]:
    """
    Lista as contas de um item específico (instituição conectada).
    """
    return await client.list_accounts(item_id)


@router.get("/transactions/{account_id}")
async def transactions(
    account_id: str,
    from_date: str | None = None,
    to_date: str | None = None,
    _: PessoaORM = Depends(get_current_user),
    client=Depends(get_pluggy),
) -> list[dict[str, Any]]:
    """
    Lista transações de uma conta.
    Opcionalmente filtra por período (from_date/to_date no formato YYYY-MM-DD).
    """
    return await client.list_transactions(account_id, from_date, to_date)


@router.get("/accounts/{account_id}/balance")
async def account_balance(
    account_id: str,
    _: PessoaORM = Depends(get_current_user),
    client=Depends(get_pluggy),
) -> dict[str, Any]:
    """
    Retorna o saldo atual de uma conta específica.
    """
    account = await client.get_account(account_id)
    # A Pluggy costuma retornar 'balance', mas deixamos fallback em 0.0
    balance = account.get("balance", 0.0)

    return {
        "accountId": account.get("id", account_id),
        "name": account.get("name"),
        "type": account.get("type"),
        "currencyCode": account.get("currencyCode"),
        "saldoAtual": balance,
    }


@router.get("/accounts/{account_id}/summary")
async def account_summary(
    account_id: str,
    from_date: str | None = None,
    to_date: str | None = None,
    _: PessoaORM = Depends(get_current_user),
    client=Depends(get_pluggy),
) -> dict[str, Any]:
    """
    Retorna um resumo da conta:
    - saldo atual
    - período analisado (se fornecido)
    - total de entradas (amount > 0)
    - total de saídas (amount < 0)
    - lista de transações
    """
    account = await client.get_account(account_id)
    transactions = await client.list_transactions(account_id, from_date, to_date)

    saldo_atual = account.get("balance", 0.0)

    entradas = 0.0
    saidas = 0.0

    for t in transactions:
        amount = t.get("amount")
        if isinstance(amount, (int, float)):
            if amount > 0:
                entradas += float(amount)
            elif amount < 0:
                saidas += float(amount)

    return {
        "accountId": account.get("id", account_id),
        "name": account.get("name"),
        "type": account.get("type"),
        "currencyCode": account.get("currencyCode"),
        "saldoAtual": saldo_atual,
        "periodo": {
            "from": from_date,
            "to": to_date,
        },
        "entradas": entradas,
        "saidas": saidas,
        "transacoes": transactions,
    }


@router.get("/_debug-auth")
async def debug_auth(
    _: PessoaORM = Depends(require_admin),
    client=Depends(get_pluggy),
) -> dict[str, Any]:
    """
    Endpoint de debug para ver o comportamento de /auth e /auth/token na Pluggy.
    """
    return await client.debug_auth()
