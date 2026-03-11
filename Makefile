.PHONY: help install dev up down clean test lint format typecheck migrate migrate-create run prod-up-blue prod-up-green prod-down prod-logs prod-ps

help:
	@echo "AgentAuth - Available commands:"
	@echo "  install        - Install production dependencies"
	@echo "  dev            - Install development dependencies"
	@echo "  up             - Start docker-compose services"
	@echo "  down           - Stop docker-compose services"
	@echo "  clean          - Remove docker volumes and containers"
	@echo "  test           - Run tests"
	@echo "  lint           - Run ruff linter"
	@echo "  format         - Format code with ruff"
	@echo "  typecheck      - Run mypy type checker"
	@echo "  migrate        - Run database migrations"
	@echo "  migrate-create - Create a new migration"
	@echo "  run            - Run development server"
	@echo "  prod-up-blue   - Start production postgres, redis, celery, and blue app slot"
	@echo "  prod-up-green  - Start production postgres, redis, celery, and green app slot"
	@echo "  prod-down      - Stop all production services"
	@echo "  prod-logs      - Tail logs from all production services"
	@echo "  prod-ps        - Show status of production services"

install:
	uv sync

dev:
	uv sync --extra dev

up:
	docker compose up -d
	@echo "Waiting for services to be healthy..."
	@sleep 5

down:
	docker compose down

clean:
	docker compose down -v

test:
	uv run pytest

test-unit:
	uv run pytest tests/unit/

test-integration:
	uv run pytest tests/integration/

test-watch:
	uv run pytest -x -q --ff

lint:
	uv run ruff check src/

format:
	uv run ruff format src/

typecheck:
	uv run mypy src/

migrate:
	uv run alembic upgrade head

migrate-create:
	@read -p "Enter migration message: " msg; \
	uv run alembic revision --autogenerate -m "$$msg"

run:
	uv run uvicorn agentauth.main:app --reload --host 0.0.0.0 --port 8000

prod-up-blue:
	docker compose -f docker-compose.prod.yml --profile blue up -d

prod-up-green:
	docker compose -f docker-compose.prod.yml --profile green up -d

prod-down:
	docker compose -f docker-compose.prod.yml --profile blue --profile green down

prod-logs:
	docker compose -f docker-compose.prod.yml --profile blue --profile green logs -f

prod-ps:
	docker compose -f docker-compose.prod.yml --profile blue --profile green ps
