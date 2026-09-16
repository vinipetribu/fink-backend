"""Essential tests for the authenticated in-memory CSV upload."""

from collections.abc import Callable, Iterator
from dataclasses import dataclass
import hashlib
from pathlib import Path
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from app.ai.transaction_classifier import (
    CATEGORIES,
    TRAINING_DATA_PATH,
    get_transaction_classifier,
)
from app.api import deps as api_deps
from app.api.csv_upload_routes import MAX_CSV_BYTES
from app.core.security_logging import logger as security_logger
from app.main import app


EXAMPLE_PATH = Path(__file__).parents[1] / "examples" / "transacoes_exemplo.csv"
USER_ID = UUID("10000000-0000-4000-8000-000000000001")
ADMIN_ID = UUID("20000000-0000-4000-8000-000000000002")


@dataclass
class FakePrincipal:
    """Minimal fictitious principal accepted by the upload dependency."""

    id_pessoa: UUID
    admin: bool


@pytest.fixture(autouse=True)
def preserve_dependency_overrides() -> Iterator[None]:
    """Restore FastAPI dependency overrides after each upload test."""
    previous = app.dependency_overrides.copy()
    try:
        yield
    finally:
        app.dependency_overrides = previous


@pytest.fixture
def client() -> TestClient:
    """Return an in-process client that does not run the application lifespan."""
    return TestClient(app)


@pytest.fixture
def authenticate() -> Callable[[bool], None]:
    """Install a local USER or ADMIN principal for one test."""

    def set_principal(admin: bool = False) -> None:
        principal = FakePrincipal(
            id_pessoa=ADMIN_ID if admin else USER_ID,
            admin=admin,
        )
        app.dependency_overrides[api_deps.get_current_user] = lambda: principal

    return set_principal


def _upload(
    client: TestClient,
    content: bytes,
    *,
    filename: str = "transacoes.csv",
):
    return client.post(
        "/api/v1/uploads/csv",
        files={"arquivo": (filename, content, "text/csv")},
    )


@pytest.mark.parametrize("admin", [False, True], ids=["USER", "ADMIN"])
def test_valid_upload_returns_metadata_and_preview(
    client: TestClient,
    authenticate: Callable[[bool], None],
    admin: bool,
) -> None:
    """Both authenticated roles can validate the fictitious example CSV."""
    authenticate(admin)
    content = EXAMPLE_PATH.read_bytes()

    response = _upload(client, content, filename=EXAMPLE_PATH.name)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["nome_original"] == "transacoes_exemplo.csv"
    assert body["sha256"] == hashlib.sha256(content).hexdigest()
    assert body["quantidade_registros"] == 3
    assert [row["categoria_sugerida"] for row in body["previa"]] == [
        "Alimentação",
        "Transporte",
        "Educação",
    ]
    assert all(0 <= row["confianca"] <= 1 for row in body["previa"])
    assert all(isinstance(row["revisao_necessaria"], bool) for row in body["previa"])
    assert body["resumo_categorias"] == {
        category: int(category in {"Alimentação", "Transporte", "Educação"})
        for category in CATEGORIES
    }


def test_upload_does_not_modify_or_expand_training_data(
    client: TestClient,
    authenticate: Callable[[bool], None],
) -> None:
    """User CSVs neither alter the versioned data nor replace the fitted model."""
    authenticate(False)
    training_before = TRAINING_DATA_PATH.read_bytes()
    classifier_before = get_transaction_classifier()

    response = _upload(client, EXAMPLE_PATH.read_bytes())

    assert response.status_code == 200
    assert TRAINING_DATA_PATH.read_bytes() == training_before
    assert get_transaction_classifier() is classifier_before


def test_upload_without_authentication_returns_401(client: TestClient) -> None:
    """Anonymous callers cannot submit a CSV."""
    response = _upload(client, EXAMPLE_PATH.read_bytes())

    assert response.status_code == 401


def test_upload_rejects_non_csv_extension(
    client: TestClient,
    authenticate: Callable[[bool], None],
) -> None:
    """Only a .csv filename is accepted."""
    authenticate(False)

    response = _upload(client, EXAMPLE_PATH.read_bytes(), filename="transacoes.txt")

    assert response.status_code == 415


def test_upload_rejects_file_larger_than_one_megabyte(
    client: TestClient,
    authenticate: Callable[[bool], None],
) -> None:
    """The byte reader stops as soon as the 1 MB limit is exceeded."""
    authenticate(False)

    response = _upload(client, b"x" * (MAX_CSV_BYTES + 1))

    assert response.status_code == 413


def test_upload_rejects_incorrect_headers(
    client: TestClient,
    authenticate: Callable[[bool], None],
) -> None:
    """All three required columns must be present."""
    authenticate(False)

    response = _upload(client, b"date,description,amount\n2026-01-01,Example,10.00\n")

    assert response.status_code == 422


@pytest.mark.parametrize(
    "row",
    [
        "not-a-date,Descrição fictícia,10.00",
        "2026-01-01,,10.00",
        "2026-01-01,Descrição fictícia,not-a-number",
    ],
    ids=["invalid-date", "empty-description", "invalid-value"],
)
def test_upload_rejects_malformed_row(
    client: TestClient,
    authenticate: Callable[[bool], None],
    row: str,
) -> None:
    """Date, description, and value are validated for every row."""
    authenticate(False)
    content = f"data,descricao,valor\n{row}\n".encode()

    response = _upload(client, content)

    assert response.status_code == 422


def test_upload_rejects_more_than_one_thousand_records(
    client: TestClient,
    authenticate: Callable[[bool], None],
) -> None:
    """At most 1,000 data rows are processed."""
    authenticate(False)
    rows = ["data,descricao,valor"]
    rows.extend(f"2026-01-01,Registro fictício {index},1.00" for index in range(1001))

    response = _upload(client, ("\n".join(rows) + "\n").encode())

    assert response.status_code == 422


def test_returned_sha256_matches_the_original_bytes(
    client: TestClient,
    authenticate: Callable[[bool], None],
) -> None:
    """The digest is calculated before decoding or normalizing the CSV."""
    authenticate(False)
    content = b"data,descricao,valor\r\n2026-02-01,Registro ficticio,7.25\r\n"

    response = _upload(client, content)

    assert response.status_code == 200
    assert response.json()["sha256"] == hashlib.sha256(content).hexdigest()


def test_upload_rejects_non_utf8_content(
    client: TestClient,
    authenticate: Callable[[bool], None],
) -> None:
    """CSV content must decode strictly as UTF-8."""
    authenticate(False)

    response = _upload(client, b"data,descricao,valor\n2026-01-01,\xff,1.00\n")

    assert response.status_code == 422


def test_upload_does_not_log_file_metadata(
    client: TestClient,
    authenticate: Callable[[bool], None],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Successful uploads emit no filename, contents, value, or full digest."""
    authenticate(False)
    content = EXAMPLE_PATH.read_bytes()
    digest = hashlib.sha256(content).hexdigest()
    security_logger.addHandler(caplog.handler)
    try:
        response = _upload(client, content, filename=EXAMPLE_PATH.name)
    finally:
        security_logger.removeHandler(caplog.handler)

    output = "\n".join(record.getMessage() for record in caplog.records)
    assert response.status_code == 200
    assert EXAMPLE_PATH.name not in output
    assert "42.50" not in output
    assert digest not in output
