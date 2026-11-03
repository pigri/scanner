# Scanner — recon/scan pipeline, two npm sub-projects: scan/ and discovery/.
# These targets WRAP each sub-project's existing package.json scripts; they do
# not reimplement anything. tsx runs the TypeScript directly, so there is no
# compile/emit step: `build` and `lint` both resolve to the type-checker, which
# is this repo's only static analysis (no eslint/prettier is configured).

DIRS := scan discovery

.DEFAULT_GOAL := help

.PHONY: help install build test lint fmt clean

help: ## List the available targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "} {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

install: ## Install dependencies in each sub-project (npm ci, no Chromium download)
	@for d in $(DIRS); do echo "==> $$d: npm ci"; \
		(cd $$d && PUPPETEER_SKIP_DOWNLOAD=1 npm ci) || exit $$?; done

build: ## Type-check each sub-project (tsx runs source directly; there is no build artifact)
	@for d in $(DIRS); do echo "==> $$d: typecheck"; \
		(cd $$d && npm run typecheck) || exit $$?; done

test: ## Run the vitest suite in each sub-project
	@for d in $(DIRS); do echo "==> $$d: test"; \
		(cd $$d && npm test) || exit $$?; done

lint: ## Static analysis — the type-checker (no eslint/prettier in this repo)
	@for d in $(DIRS); do echo "==> $$d: typecheck (lint)"; \
		(cd $$d && npm run typecheck) || exit $$?; done

fmt: ## No formatter is configured in this repo (no prettier/eslint); nothing to run
	@echo "no formatter configured (no prettier/eslint); nothing to format"

clean: ## Remove installed dependencies (node_modules is gitignored)
	@for d in $(DIRS); do echo "==> $$d: clean"; rm -rf $$d/node_modules; done
