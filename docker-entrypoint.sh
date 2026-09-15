#!/bin/sh
set -eu

global_dir=${GRAPHIT_GLOBAL_DIR:-/home/graphit/.graphit}
broker_dir="$global_dir/broker"
config_path=${GRAPHIT_BROKER_CONFIG:-$broker_dir/config.yaml}

if ! mkdir -p -- "$global_dir"; then
    echo "graphit-broker: cannot create GRAPHIT_GLOBAL_DIR '$global_dir' as graphit (uid 10001)" >&2
    exit 1
fi

if [ ! -d "$global_dir" ] || [ ! -r "$global_dir" ] || [ ! -w "$global_dir" ] || [ ! -x "$global_dir" ]; then
    echo "graphit-broker: GRAPHIT_GLOBAL_DIR '$global_dir' must be a directory readable, writable, and executable by graphit (uid 10001)" >&2
    exit 1
fi

if ! mkdir -p -- "$broker_dir"; then
    echo "graphit-broker: cannot create broker directory under GRAPHIT_GLOBAL_DIR '$global_dir' as graphit (uid 10001)" >&2
    exit 1
fi

if [ ! -d "$broker_dir" ] || [ ! -r "$broker_dir" ] || [ ! -w "$broker_dir" ] || [ ! -x "$broker_dir" ]; then
    echo "graphit-broker: broker directory '$broker_dir' must be readable, writable, and executable by graphit (uid 10001)" >&2
    exit 1
fi

if [ ! -f "$config_path" ] || [ ! -r "$config_path" ]; then
    echo "graphit-broker: GRAPHIT_BROKER_CONFIG '$config_path' must exist as a regular file readable by graphit (uid 10001)" >&2
    exit 1
fi

export GRAPHIT_BROKER_CONFIG="$config_path"

exec /usr/local/bin/graphit-broker "$@"
