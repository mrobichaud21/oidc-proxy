# oidc-proxy
Simple OIDC Proxy, fronts the login redirect and callback, then proxies to backend application.
docker buildx build --platform linux/amd64,linux/arm64 -t mrobichaud/oidc-proxy:20241119-1331 . --push