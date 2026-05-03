.DEFAULT_GOAL := help

# ── colours ──────────────────────────────────────────────────────────────────
BOLD  := \033[1m
GREEN := \033[32m
CYAN  := \033[36m
RED   := \033[31m
RESET := \033[0m

# ── helpers ───────────────────────────────────────────────────────────────────
.PHONY: help install fmt lint test check clean pre-push

help:
	@echo ""
	@echo "$(BOLD)ContextDuty — local dev commands$(RESET)"
	@echo ""
	@echo "  $(CYAN)make install$(RESET)    Install package + dev dependencies"
	@echo "  $(CYAN)make fmt$(RESET)        Auto-format code (ruff format)"
	@echo "  $(CYAN)make lint$(RESET)       Lint + import-sort check (ruff check)"
	@echo "  $(CYAN)make test$(RESET)       Run test suite (pytest)"
	@echo "  $(CYAN)make check$(RESET)      fmt + lint + test in one shot  ← run before pushing"
	@echo "  $(CYAN)make pre-push$(RESET)   Same as check (alias for git hook use)"
	@echo "  $(CYAN)make clean$(RESET)      Remove build artefacts"
	@echo ""

# ── install ───────────────────────────────────────────────────────────────────
install:
	@echo "$(BOLD)→ Installing package and dev deps...$(RESET)"
	pip install -e ".[dev]"
	@echo "$(GREEN)✓ Done$(RESET)"

# ── format ────────────────────────────────────────────────────────────────────
fmt:
	@echo "$(BOLD)→ Formatting with ruff...$(RESET)"
	ruff format src/ tests/
	ruff check src/ tests/ --fix --select I  # fix import order only
	@echo "$(GREEN)✓ Formatted$(RESET)"

# ── lint ──────────────────────────────────────────────────────────────────────
lint:
	@echo "$(BOLD)→ Linting with ruff...$(RESET)"
	ruff check src/ tests/
	ruff format src/ tests/ --check
	@echo "$(GREEN)✓ Lint passed$(RESET)"

# ── test ──────────────────────────────────────────────────────────────────────
test:
	@echo "$(BOLD)→ Running tests...$(RESET)"
	pytest --tb=short -q
	@echo "$(GREEN)✓ Tests passed$(RESET)"

# ── check (full pre-push gate) ────────────────────────────────────────────────
check: fmt lint test
	@echo ""
	@echo "$(GREEN)$(BOLD)✓ All checks passed — safe to push$(RESET)"

pre-push: check

# ── clean ─────────────────────────────────────────────────────────────────────
clean:
	@echo "$(BOLD)→ Cleaning artefacts...$(RESET)"
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info"  -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	rm -rf dist/ build/
	@echo "$(GREEN)✓ Clean$(RESET)"
