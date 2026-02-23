#!/bin/sh
set -e

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    # Enable socket activation by default (does not start the service).
    systemctl enable ghp.socket 2>/dev/null || true
fi
