.DEFAULT_GOAL := help

UV ?= uv
PYTHON := $(UV) run python
RADAR := $(UV) run threat-radar
REPORT_ROOT ?= reports/generated
AGENT_ADAPTER ?= fixture
AGENT_REPEATS ?= 3

.PHONY: help setup validate lint typecheck test acceptance eval-agents eval-coverage \
	eval-coverage-fixture eval-all check \
	build clean-build live portable agent-shadow agent-active analytics api portal \
	portal-install portal-status portal-uninstall stack-up stack-down restore-test \
	openclaw-agents-check openclaw-agents-install

help: ## Show available targets and common overrides.
	@awk 'BEGIN {FS = ":.*## "; printf "Threat Radar workflows\n\n"} /^[a-zA-Z0-9_.-]+:.*## / {printf "  %-18s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@printf "\nOverrides: REPORT_ROOT=..., AGENT_ADAPTER=fixture|openclaw|codex|claude|openai-compatible, AGENT_REPEATS=1..10\n"

setup: ## Install the project and development dependencies with uv.
	$(UV) sync --all-extras

openclaw-agents-check: ## Audit the five isolated OpenClaw role agents without changing config.
	$(PYTHON) scripts/setup_openclaw_agents.py

openclaw-agents-install: ## Install/update the scoped OpenClaw role agents.
	$(PYTHON) scripts/setup_openclaw_agents.py --apply

validate: ## Validate schemas, policies, workflows, diagrams, and repository structure.
	$(PYTHON) scripts/validate_repo.py

lint: ## Run Ruff.
	$(UV) run ruff check .

typecheck: ## Run strict mypy across application and package code.
	$(UV) run mypy apps packages

test: ## Run the complete pytest suite.
	$(UV) run pytest

acceptance: ## Run the frozen end-to-end and hostile-content acceptance suite.
	$(RADAR) eval acceptance --output $(REPORT_ROOT)/acceptance --json

eval-agents: ## Repeat the bounded-agent DAG eval and emit quality/cost/stability metrics.
	$(RADAR) eval agents --adapter $(AGENT_ADAPTER) --repeats $(AGENT_REPEATS) --output $(REPORT_ROOT)/agent-evaluation --json

eval-coverage: ## Measure source diversity and X concentration in generated reports.
	$(RADAR) eval coverage --reports $(REPORT_ROOT) --output $(REPORT_ROOT)/source-evaluation --json

eval-coverage-fixture: ## Run the source-coverage gates against the frozen multi-surface fixture.
	$(RADAR) eval coverage --reports tests/fixtures/source_coverage --output $(REPORT_ROOT)/source-evaluation-fixture --json

eval-all: acceptance eval-agents eval-coverage-fixture ## Run deterministic, agent, and source-coverage evaluations.

restore-test: ## Verify that immutable state restores and replays exactly.
	$(PYTHON) scripts/verify_restore.py --output $(REPORT_ROOT)/restore-test

check: validate lint typecheck test eval-all restore-test ## Run every local merge gate.

build: ## Build wheel and source distributions.
	$(UV) build

clean-build: ## Remove package build artifacts with uv's build backend.
	$(UV) build --clear

live: ## Run the production-store workflow using environment configuration.
	$(RADAR) live run --output $(REPORT_ROOT) --json

portable: ## Run with SQLite and local immutable object storage.
	$(RADAR) portable run --output $(REPORT_ROOT) --json

agent-shadow: ## Run portable discovery with bounded agents recorded but not applied.
	$(RADAR) portable run --output $(REPORT_ROOT) --agent-mode shadow --agent-adapter $(AGENT_ADAPTER) --json

agent-active: ## Run portable discovery and apply bounded agent analysis to report narrative.
	$(RADAR) portable run --output $(REPORT_ROOT) --agent-mode active --agent-adapter $(AGENT_ADAPTER) --json

analytics: ## Rebuild the local analytics index.
	$(RADAR) analytics sync --json

api: ## Start the loopback API.
	$(UV) run uvicorn apps.api.main:app --host 127.0.0.1 --port 8080

portal: ## Start the read-only portal.
	scripts/run-portal.sh

portal-install: ## Install the local portal service.
	scripts/install-portal-service.sh

portal-status: ## Show portal service status.
	scripts/portal-status.sh

portal-uninstall: ## Remove the local portal service.
	scripts/uninstall-portal-service.sh

stack-up: ## Start PostgreSQL, MinIO, and telemetry services.
	docker compose -f infra/docker-compose.yml up -d

stack-down: ## Stop local infrastructure services.
	docker compose -f infra/docker-compose.yml down
