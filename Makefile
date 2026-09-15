.PHONY: help install tools dev build run test harness dataplane-e2e vet lint format typecheck tidy ebpf-generate ai-triage-eval ai-triage-compare ai-triage-release ai-triage-drift ai-triage-curate ai-triage-verify sca-bench-verify \
        sca-accuracy-test sca-accuracy-smoke sca-accuracy-binary-pin sca-accuracy-frozen-sbom-verify sca-accuracy-source-native-evidence sca-accuracy-prepare sca-accuracy-cell sca-accuracy-finalize sca-accuracy-publication sca-accuracy-verify \
        rulepack-verify rulepack-replay rulepack-gate docker-build docker-up docker-down kind-smoke helm-render-test clean web-dev web-build smoke release-smoke

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
RULEPACK_ARTIFACT ?= rulepack.signed.json
RULEPACK_PUBLIC_KEY ?= rulepack-release.pub
RULEPACK_EVIDENCE ?= rulepack-gate-evidence.json
RULEPACK_EVIDENCE_PUBLIC_KEY ?= rulepack-evidence.pub
RULEPACK_PHASE ?= promotion
SCA_ACCURACY_REPOSITORY_ROOT ?= $(CURDIR)
SCA_ACCURACY_PLAN ?=
SCA_ACCURACY_SOURCE_FREEZE ?=
SCA_ACCURACY_ORACLE_CANDIDATE ?=
SCA_ACCURACY_CROSS_CHECK ?=
SCA_ACCURACY_ADJUDICATION ?=
SCA_ACCURACY_ACCOUNTABLE_REVIEW ?=
SCA_ACCURACY_FINAL_ORACLE_FREEZE ?=
SCA_ACCURACY_SOURCE_CASE_EVIDENCE ?=
SCA_ACCURACY_SOURCE_EVIDENCE_PLAN ?=
SCA_ACCURACY_SOURCE_EVIDENCE_OUTPUT ?=
SCA_ACCURACY_NATIVE_EVIDENCE ?=
SCA_ACCURACY_NATIVE_EVIDENCE_OUTPUT ?=
SCA_ACCURACY_CATALOG ?=
SCA_ACCURACY_CATALOG_OUTPUT ?=
SCA_ACCURACY_BINARY_REFERENCE ?=
SCA_ACCURACY_BINARY_PATH ?=
SCA_ACCURACY_ENGINE ?=
SCA_ACCURACY_MANIFEST_TEMPLATE_DIR ?=
SCA_ACCURACY_RATCHET_OUTPUT ?=
SCA_ACCURACY_FROZEN_SBOM ?=
SCA_ACCURACY_FROZEN_SBOM_DIGEST ?=
SCA_ACCURACY_CAPTURE_MANIFEST ?=
SCA_ACCURACY_CAPTURE_RECORD_OUTPUT ?=
SCA_ACCURACY_OUTPUT ?=
SCA_ACCURACY_REPETITION ?=
SCA_ACCURACY_RETENTION_LOCATOR ?=
SCA_ACCURACY_RETENTION_POLICY ?=
SCA_ACCURACY_LEDGER ?=
SCA_ACCURACY_ORACLE ?=
SCA_ACCURACY_RATCHET ?=
SCA_ACCURACY_PUBLICATION ?=
SCA_ACCURACY_PUBLICATION_CONTROL ?=
SCA_ACCURACY_PUBLICATION_OUTPUT ?=
SCA_ACCURACY_RESULT_OUTPUT ?=
SCA_ACCURACY_REPORT_OUTPUT ?=
SCA_ACCURACY_COMPARISON_OUTPUT ?=
SCA_ACCURACY_FALSIFIER_OUTPUT ?=
SCA_ACCURACY_EVIDENCE_SUMMARY_OUTPUT ?=
SCA_ACCURACY_FALSIFIER_SPEC ?= internal/usecase/scabench/testdata/semantic-comparison-falsifiers.json
SCA_ACCURACY_OBSERVATIONS ?=
SCA_ACCURACY_COMPARISON_PAIRS ?=

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

edr-slo: ## Run the EDR data-plane SLO / scale / chaos release gates (#594 #636)
	$(GO) test ./test/slo/... -v

dataplane-e2e: ## Run the Phase-A data-plane e2e + failure-matrix + soak harness (A7, #628)
	$(GO) test -race ./test/e2e/...

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

ebpf-generate: ## Rebuild committed Linux amd64/arm64 eBPF objects (clang + llvm-strip required)
	scripts/ebpf/build.sh

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

sca-bench-verify: ## Replay the published SCA benchmark fixture offline (no scanners)
	$(GO) test -count=1 ./cmd/synapse-bench -run '^TestPublishedBenchmarkReplay$$'
	$(GO) test -count=1 ./internal/usecase/scabench -run '^TestPublishedBenchmarkFixture'

sca-accuracy-test: ## Run focused SCA accuracy unit and command tests
	$(GO) test -count=1 ./internal/usecase/scabench ./internal/infrastructure/scabench ./cmd/synapse-sca-inputs ./cmd/synapse-sca-cycle ./cmd/synapse-sca-bench ./cmd/synapse-bench

sca-accuracy-smoke: ## Offline SCA accuracy smoke gate (no scanners)
	$(MAKE) sca-bench-verify
	$(GO) test -count=1 ./internal/usecase/scabench -run 'HistoricalReferenceInventory|SemanticComparisonFalsifierSpec|Cycle'
	$(GO) test -count=1 ./internal/infrastructure/scabench -run 'CompareBundles|Falsifier|Cycle|RepositoryAsset|Native'

sca-accuracy-binary-pin: ## Derive a benchmark binary pin and dependent ratchet bindings
	$(GO) run ./cmd/synapse-sca-inputs -mode binary-pin -repository-root "$(SCA_ACCURACY_REPOSITORY_ROOT)" -source-freeze-output "$(SCA_ACCURACY_SOURCE_FREEZE)" -manifest-template-dir "$(SCA_ACCURACY_MANIFEST_TEMPLATE_DIR)" -catalog "$(SCA_ACCURACY_CATALOG)" -ratchet "$(SCA_ACCURACY_RATCHET)" -binary-reference "$(SCA_ACCURACY_BINARY_REFERENCE)" -binary-path "$(SCA_ACCURACY_BINARY_PATH)" -engine "$(SCA_ACCURACY_ENGINE)" -catalog-output "$(SCA_ACCURACY_CATALOG_OUTPUT)" -ratchet-output "$(SCA_ACCURACY_RATCHET_OUTPUT)"

sca-accuracy-frozen-sbom-verify: ## Verify one frozen canonical CycloneDX SBOM without generating it
	@test -n "$(SCA_ACCURACY_FROZEN_SBOM)" && test -n "$(SCA_ACCURACY_FROZEN_SBOM_DIGEST)"
	@jq -e '.bomFormat == "CycloneDX" and (.specVersion | type == "string") and (.components | type == "array")' "$(SCA_ACCURACY_FROZEN_SBOM)" >/dev/null
	@tmp="$$(mktemp)"; trap 'rm -f "$$tmp"' EXIT; jq -S -c . "$(SCA_ACCURACY_FROZEN_SBOM)" > "$$tmp"; cmp -s "$(SCA_ACCURACY_FROZEN_SBOM)" "$$tmp"; test "sha256:$$(sha256sum "$(SCA_ACCURACY_FROZEN_SBOM)" | cut -d' ' -f1)" = "$(SCA_ACCURACY_FROZEN_SBOM_DIGEST)"

sca-accuracy-source-native-evidence: ## Generate write-once scanner-free source and target-native evidence
	$(GO) run ./cmd/synapse-sca-cycle -mode source-native-evidence -repository-root "$(SCA_ACCURACY_REPOSITORY_ROOT)" -source-freeze "$(SCA_ACCURACY_SOURCE_FREEZE)" -catalog "$(SCA_ACCURACY_CATALOG)" -source-evidence-plan "$(SCA_ACCURACY_SOURCE_EVIDENCE_PLAN)" -source-evidence-output "$(SCA_ACCURACY_SOURCE_EVIDENCE_OUTPUT)" -native-evidence-output "$(SCA_ACCURACY_NATIVE_EVIDENCE_OUTPUT)"

sca-accuracy-prepare: ## Verify the fully review-gated frozen source and final oracle inputs
	$(GO) run ./cmd/synapse-sca-cycle -mode prepare -repository-root "$(SCA_ACCURACY_REPOSITORY_ROOT)" -plan "$(SCA_ACCURACY_PLAN)" -source-freeze "$(SCA_ACCURACY_SOURCE_FREEZE)" -oracle-candidate "$(SCA_ACCURACY_ORACLE_CANDIDATE)" -cross-check "$(SCA_ACCURACY_CROSS_CHECK)" -adjudication "$(SCA_ACCURACY_ADJUDICATION)" -accountable-review "$(SCA_ACCURACY_ACCOUNTABLE_REVIEW)" -final-oracle-freeze "$(SCA_ACCURACY_FINAL_ORACLE_FREEZE)"

sca-accuracy-cell: ## Capture one planned cell (0 accepted, 2 retained failed attempt, 1 pre-dispatch failure)
	$(GO) run ./cmd/synapse-sca-cycle -mode cell -repository-root "$(SCA_ACCURACY_REPOSITORY_ROOT)" -source-freeze "$(SCA_ACCURACY_SOURCE_FREEZE)" -oracle-candidate "$(SCA_ACCURACY_ORACLE_CANDIDATE)" -cross-check "$(SCA_ACCURACY_CROSS_CHECK)" -adjudication "$(SCA_ACCURACY_ADJUDICATION)" -accountable-review "$(SCA_ACCURACY_ACCOUNTABLE_REVIEW)" -final-oracle-freeze "$(SCA_ACCURACY_FINAL_ORACLE_FREEZE)" -plan "$(SCA_ACCURACY_PLAN)" -catalog "$(SCA_ACCURACY_CATALOG)" -capture-manifest "$(SCA_ACCURACY_CAPTURE_MANIFEST)" -native-evidence "$(SCA_ACCURACY_NATIVE_EVIDENCE)" -capture-record-output "$(SCA_ACCURACY_CAPTURE_RECORD_OUTPUT)" -output "$(SCA_ACCURACY_OUTPUT)" -repetition "$(SCA_ACCURACY_REPETITION)" -retention-locator "$(SCA_ACCURACY_RETENTION_LOCATOR)" -retention-policy "$(SCA_ACCURACY_RETENTION_POLICY)"

sca-accuracy-finalize: ## Compare, execute falsifiers, reduce, ratchet, and render measured cycle records
	$(GO) run ./cmd/synapse-sca-cycle -mode finalize -plan "$(SCA_ACCURACY_PLAN)" -ledger "$(SCA_ACCURACY_LEDGER)" -catalog "$(SCA_ACCURACY_CATALOG)" -oracle "$(SCA_ACCURACY_ORACLE)" -ratchet "$(SCA_ACCURACY_RATCHET)" -result-output "$(SCA_ACCURACY_RESULT_OUTPUT)" -report-output "$(SCA_ACCURACY_REPORT_OUTPUT)" -comparison-output "$(SCA_ACCURACY_COMPARISON_OUTPUT)" -falsifier-output "$(SCA_ACCURACY_FALSIFIER_OUTPUT)" -falsifier-spec "$(SCA_ACCURACY_FALSIFIER_SPEC)" $(foreach item,$(SCA_ACCURACY_OBSERVATIONS),-observation "$(item)") $(foreach item,$(SCA_ACCURACY_COMPARISON_PAIRS),-comparison-pair "$(item)")

sca-accuracy-publication: ## Bind actual final artifacts into a manifest and candidate evidence summary
	$(GO) run ./cmd/synapse-sca-cycle -mode publication -plan "$(SCA_ACCURACY_PLAN)" -ledger "$(SCA_ACCURACY_LEDGER)" -publication-control "$(SCA_ACCURACY_PUBLICATION_CONTROL)" -publication-output "$(SCA_ACCURACY_PUBLICATION_OUTPUT)" -accountable-review "$(SCA_ACCURACY_ACCOUNTABLE_REVIEW)" -source-case-evidence "$(SCA_ACCURACY_SOURCE_CASE_EVIDENCE)" -native-evidence "$(SCA_ACCURACY_NATIVE_EVIDENCE)" -oracle-candidate "$(SCA_ACCURACY_ORACLE_CANDIDATE)" -cross-check "$(SCA_ACCURACY_CROSS_CHECK)" -adjudication "$(SCA_ACCURACY_ADJUDICATION)" -final-oracle-freeze "$(SCA_ACCURACY_FINAL_ORACLE_FREEZE)" -ratchet "$(SCA_ACCURACY_RATCHET)" -comparison-output "$(SCA_ACCURACY_COMPARISON_OUTPUT)" -falsifier-output "$(SCA_ACCURACY_FALSIFIER_OUTPUT)" -result-output "$(SCA_ACCURACY_RESULT_OUTPUT)" -report-output "$(SCA_ACCURACY_REPORT_OUTPUT)" -evidence-summary-output "$(SCA_ACCURACY_EVIDENCE_SUMMARY_OUTPUT)"

sca-accuracy-verify: ## Run offline SCA accuracy verification without scanners
	$(MAKE) sca-accuracy-smoke
	$(GO) test -count=1 ./cmd/synapse-sca-inputs ./cmd/synapse-sca-cycle ./internal/usecase/scabench ./internal/infrastructure/scabench

rulepack-verify: ## Verify a signed RulePack against the externally pinned release key
	$(GO) run ./cmd/synapse-cli rulepack verify --artifact $(RULEPACK_ARTIFACT) --public-key $(RULEPACK_PUBLIC_KEY)

rulepack-replay: ## Verify and replay a RulePack's positive/negative deterministic fixtures
	$(GO) run ./cmd/synapse-cli rulepack replay --artifact $(RULEPACK_ARTIFACT) --public-key $(RULEPACK_PUBLIC_KEY)

rulepack-gate: ## Evaluate attested RulePack release evidence for pre-canary, canary, or promotion
	$(GO) run ./cmd/synapse-cli rulepack gate --artifact $(RULEPACK_ARTIFACT) --public-key $(RULEPACK_PUBLIC_KEY) --evidence $(RULEPACK_EVIDENCE) --evidence-public-key $(RULEPACK_EVIDENCE_PUBLIC_KEY) --phase $(RULEPACK_PHASE)

docker-build: ## Build the API container image
	docker build -t $(IMAGE) -f deploy/Dockerfile .

docker-up: ## Start dev dependencies (Postgres + MinIO)
	docker compose -f deploy/docker-compose.yml up -d

docker-down: ## Stop dev dependencies
	docker compose -f deploy/docker-compose.yml down

kind-smoke: ## Deploy execution.mode=controlPlaneOnly to a local kind cluster and assert the control plane serves
	bash deploy/kind/kind-smoke.sh

helm-render-test: ## Validate the Helm chart renders/lints across all execution modes
	sh deploy/helm/synapse/testdata/render_test.sh

clean: ## Remove build artifacts
	rm -rf bin web/dist

web-dev: ## Run the Vite dev server (proxies /api to :8080)
	cd web && pnpm dev

web-build: ## Build the web app
	cd web && pnpm build

smoke: build ## Build then probe /healthz
	./bin/synapse-api & sleep 1; curl -s localhost:8080/healthz; kill %1

release-smoke: ## Build synapse-cli into ./bin and run a real scan from it (packaged-binary smoke)
	$(GO) build -o bin/synapse-cli ./cmd/synapse-cli
	./scripts/release/smoke-scan.sh bin
