#!/bin/sh
set -e

if command -v systemctl >/dev/null 2>&1; then
    systemctl stop ghp.service 2>/dev/null || true
    systemctl stop ghp.socket 2>/dev/null || true
    systemctl disable ghp.socket 2>/dev/null || true
fi
