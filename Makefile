# SecureBank Labs — a deliberately vulnerable banking app with 25 OWASP labs.
#
# The rule that makes this work: a toggle ARMS a lab, it is never the fix.
# `lab.<slug>=true` in application.yml stays true after you fix the lab —
# the fix is a code change at the location the lab panel names.

.DEFAULT_GOAL := help
.PHONY: help up down reset run stop build verify verify-fixed verify-all \
        matrix solutions ui ui-install test clean

APP_PORT    ?= 8080
UI_PORT     ?= 5173
TARGET      ?= http://localhost:$(APP_PORT)

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

# --- database -------------------------------------------------------------

up: ## Start postgres (docker) and wait for it to be ready
	docker compose up -d
	@echo "waiting for postgres..."
	@until docker exec securebank-db pg_isready -U securebank -d securebank >/dev/null 2>&1; \
		do sleep 1; done
	@echo "postgres is up on localhost:5432"

down: ## Stop postgres
	docker compose down

reset: ## Wipe the database volume and reseed from scratch
	docker compose down -v
	$(MAKE) up

# --- backend --------------------------------------------------------------

build: ## Compile the Spring Boot app
	cd backend && ./mvnw -q -o clean compile

run: ## Run the Spring Boot app in the foreground (port 8080)
	cd backend && ./mvnw -o spring-boot:run

stop: ## Stop a background app started by scripts/app.sh
	./scripts/app.sh stop

test: ## Run the JUnit tests
	cd backend && ./mvnw -q -o test

# --- frontend -------------------------------------------------------------

ui-install: ## Install the frontend's npm dependencies
	cd frontend && npm install --no-audit --no-fund

ui: ## Run the Vite dev server (port 5173, proxies /api to 8080)
	cd frontend && npm run dev

# --- verification ---------------------------------------------------------

verify: ## Assert every lab is still VULNERABLE (run this BEFORE you fix anything)
	python3 verify/run.py --all --expect vulnerable

verify-fixed: ## Assert every lab is FIXED (run this AFTER you fix everything)
	python3 verify/run.py --all --expect fixed

verify-all: verify verify-fixed ## Both directions

matrix: ## Prove each fix is independent: apply one at a time, expect one flip
	python3 scripts/isolation_matrix.py

solutions: ## Regenerate solutions/SOLUTIONS.md from the tested fix table
	python3 scripts/gen_solutions.py

# --- housekeeping ---------------------------------------------------------

clean: ## Remove build output
	cd backend && ./mvnw -q -o clean
	rm -rf frontend/dist frontend/node_modules/.vite
