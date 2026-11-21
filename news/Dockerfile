# Daily News web image: the pinned upstream nginx image plus current Alpine packages.
# NGINX_BASE comes from docker-compose.yml (security-watch compose-digest bumps the pin).
# SECURITY_REFRESH is a stamp: a new value rebuilds the apk layer below, which installs
# whatever Alpine has released since upstream built its image; the nginx images trail
# Alpine security fixes. Entrypoint, command and healthcheck are inherited.
ARG NGINX_BASE
FROM ${NGINX_BASE}
ARG SECURITY_REFRESH=0
RUN apk upgrade --no-cache
