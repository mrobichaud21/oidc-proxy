#!/bin/bash

# git tag -a v0.0.1 -m"Release v0.0.1"
tag=$(date "+%Y%m%d-%H%M%S")

# Build and push for multi-platform
docker buildx build --platform linux/amd64,linux/arm64 -t mrobichaud/oidc-proxy:$tag . --push