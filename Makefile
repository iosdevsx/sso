.PHONY: help build test migrate-new

help:
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

build: ## Build project
	GOWORK=off go build ./...

test: build ## Run all tests
	GOWORK=off go test ./...

migrate-new: ## Create new migration
	migrate create -ext sql -dir migrations -seq $(name)