# app/shared/seed.py
from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.shared.database import async_session_maker  # ajusta o nome se for diferente

from app.identidade.persistence.pessoa_orm import PessoaORM
from app.identidade.persistence.sessao_orm import SessaoORM  # se não usar, pode remover
from app.metas.persistence.meta_orm import MetaORM
from app.comercial.persistence.plano_orm import PlanoORM
from app.comercial.persistence.assinatura_orm import AssinaturaORM
from app.comercial.persistence.tipo_pagamento_orm import TipoPagamentoORM
from app.comercial.persistence.solicitacao_pagamento_orm import SolicitacaoPagamentoORM
from app.core.passwords import hash_password


DEMO_EMAIL = "demo@fink.dev"


async def seed_db() -> None:
    print("[SEED] Iniciando seed do banco...")
    async with async_session_maker() as session:
        # Limpa dados demo antes de popular
        await clear_demo_data(session)
        
        await seed_tipos_pagamento(session)
        await seed_planos(session)
        pessoa_demo = await seed_pessoa_demo(session)
        meta_demos = await seed_metas_demo(session, pessoa_demo)
        assinatura_demo = await seed_assinatura_demo(session, pessoa_demo)
        await seed_solicitacao_pagamento_demo(session, assinatura_demo)
    print("[SEED] Seed finalizado com sucesso!")


async def clear_demo_data(session: AsyncSession) -> None:
    """
    Remove dados demo existentes antes de popular novamente.
    Isso permite que o seed seja idempotente e sempre crie dados frescos.
    """
    print("[SEED] Limpando dados demo existentes...")
    
    # Busca pessoa demo
    result = await session.execute(
        select(PessoaORM).where(PessoaORM.email == DEMO_EMAIL)
    )
    pessoa = result.scalar_one_or_none()
    
    if pessoa:
        print(f"[SEED] Removendo pessoa demo (ID: {pessoa.id_pessoa}) e dados relacionados...")
        # Usa DELETE explícito para evitar problemas com tipos
        # O CASCADE no banco remove automaticamente: metas, alertas, sessões, assinaturas, etc.
        from sqlalchemy import delete
        stmt = delete(PessoaORM).where(PessoaORM.id_pessoa == pessoa.id_pessoa)
        await session.execute(stmt)
        await session.commit()
        print("[SEED] Dados demo removidos com sucesso!")
    else:
        print("[SEED] Nenhum dado demo encontrado para remover.")



# --------------------- TIPOS DE PAGAMENTO ---------------------


async def seed_tipos_pagamento(session: AsyncSession) -> None:
    """
    Cria alguns tipos de pagamento padrão se ainda não existirem.
    """
    # Se já existir pelo menos um, não faz nada
    result = await session.execute(select(TipoPagamentoORM).limit(1))
    exists = result.scalar_one_or_none()
    if exists:
        return

    tipos = [
        "Cartão de Crédito",
        "Cartão de Débito",
        "Pix",
        "Boleto",
    ]

    session.add_all([TipoPagamentoORM(tipo_pagamento=nome) for nome in tipos])
    await session.commit()


# -------------------------- PLANOS ----------------------------


async def seed_planos(session: AsyncSession) -> None:
    """
    Cria alguns planos comerciais padrão se ainda não existirem.
    """
    result = await session.execute(select(PlanoORM).limit(1))
    exists = result.scalar_one_or_none()
    if exists:
        return

    planos = [
        PlanoORM(
            titulo="Gratuito",
            descricao="Plano básico para começar a organizar as finanças.",
            preco=0.0,
            duracao_meses=0,
            status="ativo",
        ),
        PlanoORM(
            titulo="Essencial",
            descricao="Plano com recursos principais para acompanhamento mensal.",
            preco=19.90,
            duracao_meses=1,
            status="ativo",
        ),
        PlanoORM(
            titulo="Premium",
            descricao="Plano completo com relatórios avançados e integrações extras.",
            preco=39.90,
            duracao_meses=1,
            status="ativo",
        ),
    ]

    session.add_all(planos)
    await session.commit()


# -------------------------- PESSOA ----------------------------


async def seed_pessoa_demo(session: AsyncSession) -> PessoaORM:
    """
    Cria uma pessoa demo para testes (dados já foram limpos anteriormente).
    """
    pessoa = PessoaORM(
        email=DEMO_EMAIL,
        senha_hash=hash_password("demo123"),
        nome="Usuário Demo",
        data_nascimento=date(2000, 1, 1),
        telefone="81999999999",
        genero="nao_informado",
        estado="PE",
        cidade="Recife",
        rua="Rua de Exemplo",
        numero="123",
        cep="50000000",
        admin=False,
    )

    session.add(pessoa)
    await session.commit()
    await session.refresh(pessoa)
    print(f"[SEED] Pessoa demo criada (ID: {pessoa.id_pessoa})")
    return pessoa


# --------------------------- META -----------------------------


async def seed_metas_demo(session: AsyncSession, pessoa: PessoaORM) -> list[MetaORM]:
    """
    Cria várias metas financeiras demo para a pessoa demo.
    Retorna a lista de metas da pessoa (as já existentes + as criadas aqui).
    """
    metas_config = [
        {
            "titulo": "Reserva de Emergência",
            "categoria": "Emergência",
            "valor_alvo": Decimal("5000.00"),
            "valor_atual": Decimal("500.00"),
            # termina no fim do próximo ano
            "termina_em": date(date.today().year + 1, 12, 31),
        },
        {
            "titulo": "Viagem de Férias",
            "categoria": "Viagem",
            "valor_alvo": Decimal("8000.00"),
            "valor_atual": Decimal("2000.00"),
            "termina_em": date(date.today().year + 1, 1, 31),
        },
        {
            "titulo": "Notebook para Trabalho",
            "categoria": "Compras",
            "valor_alvo": Decimal("5000.00"),
            "valor_atual": Decimal("1500.00"),
            "termina_em": date.fromordinal(date.today().toordinal() + 180),
        },
        {
            "titulo": "Fundo de Emergência Familiar",
            "categoria": "Emergência",
            "valor_alvo": Decimal("10000.00"),
            "valor_atual": Decimal("3000.00"),
            "termina_em": date(date.today().year + 1, 6, 30),
        },
        {
            "titulo": "Viagem para Europa",
            "categoria": "Viagem",
            "valor_alvo": Decimal("15000.00"),
            "valor_atual": Decimal("5000.00"),
            "termina_em": date(date.today().year + 2, 12, 31),
        },
        {
            "titulo": "Smartphone Novo",
            "categoria": "Compras",
            "valor_alvo": Decimal("3000.00"),
            "valor_atual": Decimal("800.00"),
            "termina_em": date.fromordinal(date.today().toordinal() + 120),
        },
    ]

    metas_criadas: list[MetaORM] = []

    for cfg in metas_config:
        meta = MetaORM(
            fk_pessoa_id_pessoa=pessoa.id_pessoa,
            titulo=cfg["titulo"],
            categoria=cfg["categoria"],
            valor_alvo=cfg["valor_alvo"],
            valor_atual=cfg["valor_atual"],
            criada_em=date.today(),
            termina_em=cfg["termina_em"],
            status="em_andamento",
        )
        session.add(meta)
        metas_criadas.append(meta)

    await session.commit()
    for meta in metas_criadas:
        await session.refresh(meta)

    print(f"[SEED] {len(metas_criadas)} metas demo criadas")
    return metas_criadas

# ------------------------ ASSINATURA --------------------------


async def seed_assinatura_demo(session: AsyncSession, pessoa: PessoaORM) -> AssinaturaORM:
    """
    Cria uma assinatura demo para a pessoa demo (dados já foram limpos anteriormente).
    """
    # Buscar plano 'Essencial' para vincular
    result_plano = await session.execute(
        select(PlanoORM).where(PlanoORM.titulo == "Essencial")
    )
    plano = result_plano.scalar_one_or_none()
    if not plano:
        # fallback: pega qualquer plano
        result_plano = await session.execute(select(PlanoORM).limit(1))
        plano = result_plano.scalar_one()

    hoje = date.today()
    termina = date.fromordinal(hoje.toordinal() + 30)  # 30 dias

    assinatura = AssinaturaORM(
        fk_pessoa_id_pessoa=pessoa.id_pessoa,
        fk_plano_id_plano=plano.id_plano,
        comeca_em=hoje,
        termina_em=termina,
        status="ativa",
    )

    session.add(assinatura)
    await session.commit()
    await session.refresh(assinatura)
    print(f"[SEED] Assinatura demo criada (Plano: {plano.titulo})")
    return assinatura


# ------------------- SOLICITAÇÃO PAGAMENTO -------------------


async def seed_solicitacao_pagamento_demo(
    session: AsyncSession,
    assinatura: AssinaturaORM,
) -> None:
    """
    Cria uma solicitação de pagamento demo (dados já foram limpos anteriormente).
    """
    # Escolher um tipo de pagamento (ex.: 'Pix')
    result_tipo = await session.execute(
        select(TipoPagamentoORM).where(TipoPagamentoORM.tipo_pagamento == "Pix")
    )
    tipo = result_tipo.scalar_one_or_none()
    if not tipo:
        # fallback: pega qualquer tipo
        result_tipo = await session.execute(select(TipoPagamentoORM).limit(1))
        tipo = result_tipo.scalar_one()

    solicitacao = SolicitacaoPagamentoORM(
        fk_tipo_pagamento_id_pagamento=tipo.id_pagamento,
        fk_assinatura_id_assinatura=assinatura.id_assinatura,
        data_hora=datetime.utcnow(),
    )

    session.add(solicitacao)
    await session.commit()
    print("[SEED] Solicitação de pagamento demo criada")

