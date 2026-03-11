"""Unit tests for RequestLoggingMiddleware."""

import pytest
import pytest_asyncio
from fastapi import FastAPI, HTTPException, Request
from httpx import ASGITransport, AsyncClient
from structlog.testing import capture_logs


@pytest_asyncio.fixture
async def log_app() -> FastAPI:
    """Minimal FastAPI app with RequestLoggingMiddleware for isolated unit tests."""
    from agentauth.api.middleware import RequestLoggingMiddleware

    app = FastAPI()
    app.add_middleware(RequestLoggingMiddleware)

    @app.get("/health")
    async def health():
        return {"status": "healthy"}

    @app.get("/ready")
    async def ready():
        return {"status": "ready"}

    @app.get("/ping")
    async def ping():
        return {"pong": True}

    @app.get("/items/{item_id}")
    async def get_item(item_id: str):
        raise HTTPException(status_code=404, detail="Item not found")

    @app.get("/error")
    async def trigger_error():
        raise HTTPException(status_code=500, detail="Internal server error")

    @app.get("/with-agent-id")
    async def with_agent_id(request: Request):
        request.state.agent_id = "test-agent-uuid"
        return {"ok": True}

    return app


def _http_request_logs(cap_logs: list) -> list:
    return [e for e in cap_logs if e.get("event") == "http_request"]


@pytest.mark.asyncio
class TestRequestLoggingMiddleware:
    async def test_request_logging_logs_method_path_status_duration(
        self, log_app: FastAPI
    ):
        with capture_logs() as cap_logs:
            async with AsyncClient(
                transport=ASGITransport(app=log_app), base_url="http://test"
            ) as client:
                response = await client.get("/ping")

        assert response.status_code == 200
        entries = _http_request_logs(cap_logs)
        assert len(entries) == 1
        entry = entries[0]
        assert entry["method"] == "GET"
        assert entry["path"] == "/ping"
        assert entry["status_code"] == 200
        assert "duration_ms" in entry
        assert isinstance(entry["duration_ms"], float)
        assert "request_id" in entry

    async def test_request_id_generated_when_absent(self, log_app: FastAPI):
        import re

        uuid4_re = re.compile(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            re.IGNORECASE,
        )
        with capture_logs() as cap_logs:
            async with AsyncClient(
                transport=ASGITransport(app=log_app), base_url="http://test"
            ) as client:
                response = await client.get("/ping")

        entries = _http_request_logs(cap_logs)
        assert len(entries) == 1
        generated_id = entries[0]["request_id"]
        assert uuid4_re.match(generated_id), f"Not a UUID4: {generated_id}"
        assert response.headers.get("x-request-id") == generated_id

    async def test_request_id_propagated_from_header(self, log_app: FastAPI):
        custom_id = "my-custom-request-id-123"
        with capture_logs() as cap_logs:
            async with AsyncClient(
                transport=ASGITransport(app=log_app), base_url="http://test"
            ) as client:
                response = await client.get(
                    "/ping", headers={"X-Request-ID": custom_id}
                )

        entries = _http_request_logs(cap_logs)
        assert len(entries) == 1
        assert entries[0]["request_id"] == custom_id
        assert response.headers.get("x-request-id") == custom_id

    async def test_x_request_id_set_on_response(self, log_app: FastAPI):
        with capture_logs():
            async with AsyncClient(
                transport=ASGITransport(app=log_app), base_url="http://test"
            ) as client:
                response = await client.get("/ping")

        assert "x-request-id" in response.headers
        assert response.headers["x-request-id"] != ""

    async def test_health_endpoint_not_logged(self, log_app: FastAPI):
        with capture_logs() as cap_logs:
            async with AsyncClient(
                transport=ASGITransport(app=log_app), base_url="http://test"
            ) as client:
                response = await client.get("/health")

        assert response.status_code == 200
        assert _http_request_logs(cap_logs) == []

    async def test_ready_endpoint_not_logged(self, log_app: FastAPI):
        with capture_logs() as cap_logs:
            async with AsyncClient(
                transport=ASGITransport(app=log_app), base_url="http://test"
            ) as client:
                response = await client.get("/ready")

        assert response.status_code == 200
        assert _http_request_logs(cap_logs) == []

    async def test_404_unregistered_route_logged_at_debug(self, log_app: FastAPI):
        with capture_logs() as cap_logs:
            async with AsyncClient(
                transport=ASGITransport(app=log_app), base_url="http://test"
            ) as client:
                response = await client.get("/totally/unknown/route")

        assert response.status_code == 404
        entries = _http_request_logs(cap_logs)
        assert len(entries) == 1
        assert entries[0]["log_level"] == "debug"
        assert entries[0]["path"] == "/totally/unknown/route"

    async def test_404_registered_route_logged_at_warning(self, log_app: FastAPI):
        with capture_logs() as cap_logs:
            async with AsyncClient(
                transport=ASGITransport(app=log_app), base_url="http://test"
            ) as client:
                response = await client.get("/items/nonexistent-item")

        assert response.status_code == 404
        entries = _http_request_logs(cap_logs)
        assert len(entries) == 1
        assert entries[0]["log_level"] == "warning"
        assert entries[0]["path"] == "/items/nonexistent-item"

    async def test_5xx_logged_at_error(self, log_app: FastAPI):
        with capture_logs() as cap_logs:
            async with AsyncClient(
                transport=ASGITransport(app=log_app), base_url="http://test"
            ) as client:
                response = await client.get("/error")

        assert response.status_code == 500
        entries = _http_request_logs(cap_logs)
        assert len(entries) == 1
        assert entries[0]["log_level"] == "error"
        assert entries[0]["status_code"] == 500

    async def test_agent_id_included_when_set_on_state(self, log_app: FastAPI):
        with capture_logs() as cap_logs:
            async with AsyncClient(
                transport=ASGITransport(app=log_app), base_url="http://test"
            ) as client:
                response = await client.get("/with-agent-id")

        assert response.status_code == 200
        entries = _http_request_logs(cap_logs)
        assert len(entries) == 1
        assert entries[0].get("agent_id") == "test-agent-uuid"

    async def test_agent_id_omitted_when_not_authenticated(self, log_app: FastAPI):
        with capture_logs() as cap_logs:
            async with AsyncClient(
                transport=ASGITransport(app=log_app), base_url="http://test"
            ) as client:
                await client.get("/ping")

        entries = _http_request_logs(cap_logs)
        assert len(entries) == 1
        assert "agent_id" not in entries[0]

    async def test_2xx_logged_at_info(self, log_app: FastAPI):
        with capture_logs() as cap_logs:
            async with AsyncClient(
                transport=ASGITransport(app=log_app), base_url="http://test"
            ) as client:
                await client.get("/ping")

        entries = _http_request_logs(cap_logs)
        assert len(entries) == 1
        assert entries[0]["log_level"] == "info"
