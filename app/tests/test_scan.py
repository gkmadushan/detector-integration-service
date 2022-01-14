from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from main import app
from utils.database import Base
from dependencies import get_db, get_token_header


def override_get_token_header():
    return True


app.dependency_overrides[get_token_header] = override_get_token_header

client = TestClient(app)


def test_get_types_200():
    response = client.get("/v1/scans/types")
    assert response.status_code == 200


def test_get_classes_200():
    response = client.get("/v1/scans/classes")
    assert response.status_code == 200


def test_get_os_200():
    response = client.get("/v1/scans/os")
    assert response.status_code == 200


def test_get_graphs_200():
    response = client.get("/v1/scans/graphs")
    assert response.status_code == 200


def test_get_scan_404():
    response = client.get("/v1/scans/c2fa95a4-ee1f-4910-b7be-ae3c81e91508")
    assert response.status_code == 404


def test_scan_422():
    response = client.post("/v1/scans")
    assert response.status_code == 422
