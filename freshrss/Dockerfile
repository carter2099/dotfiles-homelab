# FreshRSS derived image: the pinned upstream image plus current Debian packages.
# FRESHRSS_BASE comes from docker-compose.yml (steward P1 bumps the pin there).
# SECURITY_REFRESH is a stamp: a new value rebuilds the apt layer below, which
# installs whatever Debian (incl. trixie-security) has released since upstream
# built its image. Entrypoint, command, user and healthcheck are inherited.
ARG FRESHRSS_BASE
FROM ${FRESHRSS_BASE}
ARG SECURITY_REFRESH=0
RUN set -eux; \
    export DEBIAN_FRONTEND=noninteractive; \
    apt-get update; \
    apt-get -y -o Dpkg::Options::=--force-confold upgrade; \
    rm -rf /var/lib/apt/lists/*
