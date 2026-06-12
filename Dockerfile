FROM alpine:3.20

# bash       — the script itself (and /dev/tcp probes)
# bind-tools — dig, for the router-vs-public DNS probes
# iputils    — ping with -W timeout semantics
# musl-utils — getent, for the system-resolver probe
# coreutils  — timeout
# iproute2 — busybox's ip lacks `-br` and friends used in snapshots
RUN apk add --no-cache bash curl bind-tools iputils musl-utils coreutils mtr iproute2

COPY netwatch.sh /usr/local/bin/netwatch.sh

ENV NETWATCH_DIR=/data
VOLUME /data

ENTRYPOINT ["/usr/local/bin/netwatch.sh"]
