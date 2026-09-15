FROM nvidia/cuda:12.8.1-cudnn-runtime-ubuntu24.04

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libgomp1 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 graphit \
    && useradd --uid 10001 --gid graphit --home-dir /home/graphit --create-home --shell /usr/sbin/nologin graphit \
    && install -d -o graphit -g graphit -m 0700 \
        /home/graphit/.graphit \
        /home/graphit/.graphit/broker

COPY --chown=graphit:graphit --chmod=0755 graphit-broker /usr/local/bin/graphit-broker
COPY --chown=graphit:graphit --chmod=0755 docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

ENV GRAPHIT_GLOBAL_DIR=/home/graphit/.graphit \
    GRAPHIT_BROKER_CONFIG=/home/graphit/.graphit/broker/config.yaml

WORKDIR /home/graphit/.graphit/broker
USER graphit:graphit
EXPOSE 8080
VOLUME ["/home/graphit/.graphit/broker"]
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=3 \
    CMD /usr/local/bin/graphit-broker --healthcheck "http://127.0.0.1:8080/readyz"
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
