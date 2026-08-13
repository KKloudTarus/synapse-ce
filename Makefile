.PHONY: help install tools dev build run test harness vet lint format typecheck tidy ai-triage-eval ai-triage-compare ai-triage-drift \
        docker-build docker-up docker-down clean web-dev web-build smoke

GO ?= go
IMAGE ?= synapse-api:dev
AI_EVAL_DATASET ?= internal/usecase/sca/testdata/fptriage-golden-v1.json
AI_EVAL_OUTPUT ?= ai-triage-eval.json
AI_EVAL_BASELINE ?= ai-triage-baseline.json
AI_EVAL_CANDIDATE ?= ai-triage-candidate.json
AI_EVAL_COMPARISON ?= ai-triage-comparison.json
AI_DRIFT_BASELINE ?= ai-triage-drift-baseline.json
AI_DRIFT_OBSERVED ?= ai-triage-observability.json
AI_DRIFT_OUTPUT ?= ai-triage-drift-report.json

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

install: ## Install Go + web dependencies
	$(GO) mod download
	cd web && pnpm install

tools: ## Install external scan binaries (syft+grype into ./bin; add RECON=1 for recon tools)
	scripts/install-tools.sh $(if $(RECON),--recon,)

dev: ## Run API + web dev servers together
	@$(MAKE) -j2 run web-dev

build: ## Build all Go binaries into ./bin
	$(GO) build -o bin/ ./cmd/...

run: ## Run the API server (:8080)
	$(GO) run ./cmd/synapse-api

test: ## Run Go tests
	$(GO) test ./...

harness: ## Run the hostile tenant-isolation harness
	$(GO) test ./internal/adapter/httpapi -run '^TestHostileHarness$$'

vet: ## Run go vet
	$(GO) vet ./...

lint: ## Run golangci-lint (install separately)
	golangci-lint run

format: ## Format Go code
	gofmt -w .

typecheck: ## Static checks: go vet + web tsc --noEmit
	$(GO) vet ./...
	cd web && pnpm run typecheck

tidy: ## Tidy go.mod / go.sum
	$(GO) mod tidy

ai-triage-eval: ## Evaluate FP triage against the versioned golden dataset (requires two model IDs)
	$(GO) run ./cmd/synapse-fptriage-eval --dataset $(AI_EVAL_DATASET) --output $(AI_EVAL_OUTPUT)

ai-triage-compare: ## Compare candidate and baseline AI-triage shadow reports for promotion review
	$(GO) run ./cmd/synapse-fptriage-compare --baseline $(AI_EVAL_BASELINE) --candidate $(AI_EVAL_CANDIDATE) --output $(AI_EVAL_COMPARISON)

ai-triage-drift: ## Compare AI triage input distribution with a human-approved baseline
	$(GO) run ./cmd/synapse-fptriage-drift --baseline $(AI_DRIFT_BASELINE) --observed $(AI_DRIFT_OBSERVED) --output $(AI_DRIFT_OUTPUT)

docker-build: ## Build the API container image
	docker build -t $(IMAGE) -f deploy/Dockerfile .

docker-up: ## Start dev dependencies (Postgres + MinIO)
	docker compose -f deploy/docker-compose.yml up -d

docker-down: ## Stop dev dependencies
	docker compose -f deploy/docker-compose.yml down

clean: ## Remove build artifacts
	rm -rf bin web/dist

web-dev: ## Run the Vite dev server (proxies /api to :8080)
	cd web && pnpm dev

web-build: ## Build the web app
	cd web && pnpm build

smoke: build ## Build then probe /healthz
	./bin/synapse-api & sleep 1; curl -s localhost:8080/healthz; kill %1
