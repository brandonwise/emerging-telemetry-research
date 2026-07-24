.PHONY: validate test lint typecheck acceptance restore-test api analytics portal portal-install portal-status portal-uninstall stack-up stack-down

validate:
	python scripts/validate_repo.py

lint:
	ruff check .

typecheck:
	mypy apps packages

test:
	pytest

acceptance:
	python scripts/run_acceptance.py --output reports/generated/acceptance

restore-test:
	python scripts/verify_restore.py --output reports/generated/restore-test

api:
	uvicorn apps.api.main:app --host 127.0.0.1 --port 8080

analytics:
	threat-radar analytics sync --json

portal:
	scripts/run-portal.sh

portal-install:
	scripts/install-portal-service.sh

portal-status:
	scripts/portal-status.sh

portal-uninstall:
	scripts/uninstall-portal-service.sh

stack-up:
	docker compose -f infra/docker-compose.yml up -d

stack-down:
	docker compose -f infra/docker-compose.yml down
