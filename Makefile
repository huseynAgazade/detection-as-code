# Everything the pipeline does, runnable locally with the same arguments CI uses.
# If a target passes here, the corresponding job passes there.

PYTHON ?= python3
ENV    ?=

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[1m%-14s\033[0m %s\n", $$1, $$2}'

.PHONY: install
install: ## Install pipeline and development dependencies
	$(PYTHON) -m pip install -r requirements-dev.txt

.PHONY: validate
validate: ## Stage 1: structure, quality gates, sensitive-value scan
	$(PYTHON) -m pipelines.validate

.PHONY: validate-strict
validate-strict: ## Stage 1 with warnings promoted to errors
	$(PYTHON) -m pipelines.validate --strict

.PHONY: review
review: ## Stage 2: AI quality review of the rules changed against main
	$(PYTHON) -m pipelines.review --changed-from origin/main --markdown review.md --json review.json

.PHONY: review-all
review-all: ## Stage 2 across the whole catalogue (costs real money)
	$(PYTHON) -m pipelines.review --all --markdown review.md --json review.json

.PHONY: build
build: ## Stage 3: render deployable packages into dist/
	$(PYTHON) -m pipelines.build $(if $(ENV),--environment $(ENV),)

.PHONY: coverage
coverage: ## Regenerate docs/coverage.md from the catalogue
	$(PYTHON) -m pipelines.tools.coverage --output docs/coverage.md

.PHONY: new
new: ## Scaffold a rule: make new CATEGORY=identity/active_directory SUBJECT=AD NAME="Rule Name"
	$(PYTHON) -m pipelines.tools.new_detection --category "$(CATEGORY)" --subject "$(SUBJECT)" --name "$(NAME)"

.PHONY: test
test: ## Run the pipeline test suite
	$(PYTHON) -m pytest

.PHONY: lint
lint: ## Lint the pipeline code
	$(PYTHON) -m ruff check pipelines tests

.PHONY: check
check: lint test validate ## Everything that runs without an API key

.PHONY: clean
clean: ## Remove build and review artefacts
	rm -rf dist review.md review.json .pytest_cache .ruff_cache
