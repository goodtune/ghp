# Installation

## Requirements

- Go 1.24+ (build from source)
- PostgreSQL 14+ (production) or SQLite (development)

## Build from Source

    git clone https://github.com/goodtune/ghp.git
    cd ghp
    make build

This produces a statically linked `ghp` binary (`CGO_ENABLED=0`).

## Verify

    ./ghp version
