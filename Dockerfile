FROM buildpack-deps:noble-curl AS certificates
FROM certificates AS package
COPY installer-package/graphit-broker-linux-amd64.tar.gz /tmp/broker.tar.gz
RUN mkdir /package && tar -xzf /tmp/broker.tar.gz -C /package \
    && chmod 0755 /package/graphit-broker-linux-amd64/graphit-broker

FROM ubuntu:24.04

COPY --from=certificates /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

RUN groupadd --gid 10001 graphit \
    && useradd --uid 10001 --gid graphit --home-dir /home/graphit --create-home --shell /usr/sbin/nologin graphit \
    && install -d -o graphit -g graphit -m 0700 \
        /home/graphit/.graphit \
        /home/graphit/.graphit/broker \
        /var/lib/graphit \
        /var/lib/graphit/hub

# Preserve the release layout: optional module, relative runtime and notices.
COPY --from=package --chown=graphit:graphit /package/graphit-broker-linux-amd64/ /usr/local/bin/
COPY --chown=graphit:graphit --chmod=0755 docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

ENV GRAPHIT_GLOBAL_DIR=/home/graphit/.graphit \
    GRAPHIT_BROKER_CONFIG=/home/graphit/.graphit/broker/config.yaml \
    GRAPHIT_BROKER_HEALTHCHECK_URL=http://127.0.0.1:8080/readyz

WORKDIR /home/graphit/.graphit/broker
USER graphit:graphit
EXPOSE 8080
# The second volume holds Hub objects when a storage route uses the filesystem driver. It stays
# empty otherwise, and its ownership is what lets a named volume be writable by graphit.
VOLUME ["/home/graphit/.graphit/broker", "/var/lib/graphit/hub"]
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=3 \
    CMD env -u GRAPHIT_BROKER_CONFIG /usr/local/bin/graphit-broker --healthcheck "$GRAPHIT_BROKER_HEALTHCHECK_URL"
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
