"""Deterministic local classifier for fictitious transaction descriptions."""

from __future__ import annotations

import csv
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Final, Literal, cast

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression


TransactionCategory = Literal[
    "Alimentação",
    "Transporte",
    "Moradia",
    "Saúde",
    "Educação",
    "Lazer",
    "Outros",
]

CATEGORIES: Final[tuple[TransactionCategory, ...]] = (
    "Alimentação",
    "Transporte",
    "Moradia",
    "Saúde",
    "Educação",
    "Lazer",
    "Outros",
)
RANDOM_STATE: Final = 42
MAX_DESCRIPTION_LENGTH: Final = 255
CONFIDENCE_THRESHOLD: Final = 0.55
MIN_KNOWN_TOKEN_RATIO: Final = 0.5
TRAINING_DATA_PATH: Final = Path(__file__).parent / "data" / "training_transactions.csv"


@dataclass(frozen=True)
class ClassificationResult:
    """One category suggestion and the signals used for human review."""

    categoria_sugerida: TransactionCategory
    confianca: float
    revisao_necessaria: bool


def _load_training_data() -> tuple[list[str], list[TransactionCategory]]:
    descriptions: list[str] = []
    categories: list[TransactionCategory] = []
    with TRAINING_DATA_PATH.open(encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream):
            category = row["categoria"]
            if category not in CATEGORIES:
                raise ValueError(f"Categoria de treinamento fora da allowlist: {category}")
            descriptions.append(row["descricao"])
            categories.append(cast(TransactionCategory, category))

    if set(categories) != set(CATEGORIES):
        raise ValueError("O treinamento deve conter todas as categorias permitidas")
    return descriptions, categories


class TransactionClassifier:
    """TF-IDF plus logistic regression trained only on the versioned dataset."""

    def __init__(self) -> None:
        descriptions, categories = _load_training_data()
        self.vectorizer = TfidfVectorizer(
            lowercase=True,
            strip_accents="unicode",
            ngram_range=(1, 2),
        )
        training_vectors = self.vectorizer.fit_transform(descriptions)
        self.model = LogisticRegression(
            C=8.0,
            max_iter=1_000,
            random_state=RANDOM_STATE,
            solver="lbfgs",
        )
        self.model.fit(training_vectors, categories)
        self._analyzer = self.vectorizer.build_analyzer()

    def classify(self, description: str) -> ClassificationResult:
        """Suggest a category without changing data or learning from the input."""
        normalized = description.strip()
        if not normalized or len(normalized) > MAX_DESCRIPTION_LENGTH:
            return ClassificationResult("Outros", 0.0, True)

        tokens = self._analyzer(normalized)
        known_tokens = [token for token in tokens if token in self.vectorizer.vocabulary_]
        if not tokens or not known_tokens:
            return ClassificationResult("Outros", 0.0, True)

        vector = self.vectorizer.transform([normalized])
        probabilities = self.model.predict_proba(vector)[0]
        best_index = int(probabilities.argmax())
        predicted = str(self.model.classes_[best_index])
        if predicted not in CATEGORIES:
            return ClassificationResult("Outros", 0.0, True)

        confidence = round(float(probabilities[best_index]), 4)
        known_token_ratio = len(known_tokens) / len(tokens)
        needs_review = (
            confidence < CONFIDENCE_THRESHOLD
            or known_token_ratio < MIN_KNOWN_TOKEN_RATIO
        )
        return ClassificationResult(
            categoria_sugerida=cast(TransactionCategory, predicted),
            confianca=confidence,
            revisao_necessaria=needs_review,
        )


@lru_cache(maxsize=1)
def get_transaction_classifier() -> TransactionClassifier:
    """Train once per process from immutable, versioned fictitious examples."""
    return TransactionClassifier()
