.PHONY: build test vet vet-cross lint check clean run migrate man scoperig scoperig-validate

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

## vet-cross: go vet for the non-host targets so build-tagged files cannot rot
vet-cross:
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet ./...
	GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go vet ./...
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go vet ./...

## lint: run golangci-lint (if installed)
lint:
	golangci-lint run ./...

## check: run tests, vet and cross-compile vet
check: test vet vet-cross

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
# The commit is stamped explicitly: Go's VCS stamping can read the parent
# checkout when building inside a git worktree.
RIG_COMMIT := $(shell git rev-parse HEAD 2>/dev/null)$(shell git diff --quiet HEAD -- 2>/dev/null || echo -dirty)
scoperig:
	CGO_ENABLED=0 go build -ldflags '-X github.com/goodtune/ghp/tools/scoperig/exec.Commit=$(RIG_COMMIT)' -o scoperig ./tools/scoperig

## scoperig-validate: offline validation of rig/ scenarios
scoperig-validate:
	env -u GHP_SERVER_URL -u GHP_USER_TOKEN go run ./tools/scoperig validate
