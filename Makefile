.PHONY: validate test lint typecheck docs-up stack-up stack-down

validate:
	python scripts/validate_repo.py

lint:
	ruff check .

typecheck:
	mypy apps packages

test:
	pytest

stack-up:
	docker compose -f infra/docker-compose.yml up -d

stack-down:
	docker compose -f infra/docker-compose.yml down
