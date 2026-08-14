.PHONY: help install tools dev build run test harness vet lint format typecheck tidy ai-triage-eval ai-triage-compare ai-triage-release ai-triage-drift ai-triage-curate ai-triage-verify \
        docker-build docker-up docker-down clean web-dev web-build smoke

GO ?= go
IMAGE ?= synapse-api:dev
AI_EVAL_DATASET ?= internal/usecase/sca/testdata/fptriage-golden-v2.json
AI_EVAL_OUTPUT ?= ai-triage-eval.json
AI_EVAL_BASELINE ?= ai-triage-baseline.json
AI_EVAL_CANDIDATE ?= ai-triage-candidate.json
AI_EVAL_COMPARISON ?= ai-triage-comparison.json
AI_RELEASE_MANIFEST ?= ai-triage-release-manifest.json
AI_RELEASE_LEDGER ?=
AI_RELEASE_OUTPUT ?= ai-triage-release-ledger.json
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

ai-triage-release: ## Append a PM/Security-approved AI-triage promotion to a new release ledger
	$(GO) run ./cmd/synapse-fptriage-release --manifest $(AI_RELEASE_MANIFEST) $(if $(AI_RELEASE_LEDGER),--ledger $(AI_RELEASE_LEDGER),) --comparison $(AI_EVAL_COMPARISON) --baseline $(AI_EVAL_BASELINE) --candidate $(AI_EVAL_CANDIDATE) --output $(AI_RELEASE_OUTPUT)

ai-triage-drift: ## Compare AI triage input distribution with a human-approved baseline
	$(GO) run ./cmd/synapse-fptriage-drift --baseline $(AI_DRIFT_BASELINE) --observed $(AI_DRIFT_OBSERVED) --output $(AI_DRIFT_OUTPUT)

ai-triage-verify: ## Reproducibly verify AI-triage eval + shadow gate offline (no models, no prod data)
	$(GO) build ./cmd/synapse-fptriage-eval ./cmd/synapse-fptriage-compare ./cmd/synapse-fptriage-drift ./cmd/synapse-fptriage-release ./cmd/synapse-fptriage-curate
	$(GO) test -count=1 ./internal/usecase/sca/ -run 'AIEvaluation|FPTriage|AITriage|GoldenDataset|GatePolicy'
	$(GO) test -count=1 ./internal/usecase/fptriage/...

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
