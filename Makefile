.PHONY: build test vet lint check clean run migrate man scoperig scoperig-validate

# Build configuration
BINARY  := ghp
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)

## build: compile the binary
build:
	CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' -o $(BINARY) ./cmd/ghp

## test: run all unit tests
test:
	go test ./...

## vet: run go vet
vet:
	go vet ./...

## lint: run golangci-lint (if installed)
lint:
	golangci-lint run ./...

## check: run tests and vet
check: test vet

## clean: remove build artifacts
clean:
	rm -f $(BINARY)

## run: build and start the server (pass CONFIG=path/to/config.yaml)
run: build
	./$(BINARY) serve $(if $(CONFIG),--config $(CONFIG))

## migrate: run database migrations (pass CONFIG=path/to/config.yaml)
migrate: build
	./$(BINARY) migrate $(if $(CONFIG),--config $(CONFIG))

## man: generate man pages
man: build
	./$(BINARY) doc --output doc/man1

## scoperig: build the scope regression rig (operator tool, not shipped)
scoperig:
	CGO_ENABLED=0 go build -o scoperig ./tools/scoperig

## scoperig-validate: offline validation of rig/ scenarios
scoperig-validate:
	env -u GHP_SERVER_URL -u GHP_USER_TOKEN go run ./tools/scoperig validate
