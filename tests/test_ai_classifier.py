"""Essential characterization tests for the local transaction classifier."""

import pytest

from app.ai.transaction_classifier import CATEGORIES, TransactionClassifier


@pytest.fixture(scope="module")
def classifier() -> TransactionClassifier:
    """Train once from the small, fictitious, versioned dataset."""
    return TransactionClassifier()


@pytest.mark.parametrize(
    ("description", "expected_category"),
    [
        ("almoço no restaurante", "Alimentação"),
        ("corrida de aplicativo", "Transporte"),
        ("aluguel do apartamento", "Moradia"),
        ("consulta médica", "Saúde"),
        ("mensalidade da escola", "Educação"),
        ("ingresso de cinema", "Lazer"),
        ("tarifa bancária", "Outros"),
    ],
)
def test_representative_descriptions_receive_coherent_categories(
    classifier: TransactionClassifier,
    description: str,
    expected_category: str,
) -> None:
    """Clear examples map to the intended fixed categories."""
    assert classifier.classify(description).categoria_sugerida == expected_category


def test_result_is_deterministic(classifier: TransactionClassifier) -> None:
    """The fixed training data and random seed produce repeatable output."""
    first = classifier.classify("compra no supermercado")
    second = TransactionClassifier().classify("compra no supermercado")

    assert first == second


@pytest.mark.parametrize(
    "description",
    [
        "almoço no restaurante",
        "qzxv blorf 9988 ???",
        "mercado cinema combustível promoção",
    ],
)
def test_category_always_belongs_to_allowlist(
    classifier: TransactionClassifier,
    description: str,
) -> None:
    """Even hostile or unknown text cannot create an arbitrary category."""
    assert classifier.classify(description).categoria_sugerida in CATEGORIES


@pytest.mark.parametrize(
    "description",
    [
        "",
        "qzxv blorf 9988 ???",
        "mercado cinema combustível promoção",
    ],
)
def test_unknown_ambiguous_or_empty_description_requires_review(
    classifier: TransactionClassifier,
    description: str,
) -> None:
    """Low-signal and conflicting descriptions are routed to human review."""
    assert classifier.classify(description).revisao_necessaria is True
