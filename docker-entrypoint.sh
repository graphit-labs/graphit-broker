#!/bin/sh
set -eu

global_dir=${GRAPHIT_GLOBAL_DIR:-/home/graphit/.graphit}
broker_dir="$global_dir/broker"
config_path=${GRAPHIT_BROKER_CONFIG:-$broker_dir/config.yaml}
export GRAPHIT_GLOBAL_DIR="$global_dir" GRAPHIT_BROKER_CONFIG="$config_path"

run_hooks() {
    phase=$1
    dir="/docker-entrypoint.d/$phase"
    [ -e "$dir" ] || return 0
    if [ ! -d "$dir" ] || [ ! -r "$dir" ] || [ ! -x "$dir" ]; then
        echo "graphit-broker: hook directory '$dir' must be readable and traversable by graphit (uid 10001)" >&2
        exit 1
    fi

    for script in "$dir"/*; do
        [ -e "$script" ] || [ -L "$script" ] || continue
        if [ ! -f "$script" ]; then
            echo "graphit-broker: hook '$script' must be a regular file" >&2
            exit 1
        fi
        echo "graphit-broker: running hook '$script'" >&2
        case $script in
            *.sh)
                if [ ! -r "$script" ]; then
                    echo "graphit-broker: hook '$script' must be readable by graphit (uid 10001)" >&2
                    exit 1
                fi
                if /bin/sh "$script"; then :; else
                    status=$?
                    echo "graphit-broker: hook '$script' failed with exit code $status" >&2
                    exit "$status"
                fi
                ;;
            *)
                if [ ! -x "$script" ]; then
                    echo "graphit-broker: hook '$script' must be executable by graphit (uid 10001)" >&2
                    exit 1
                fi
                if "$script"; then :; else
                    status=$?
                    echo "graphit-broker: hook '$script' failed with exit code $status" >&2
                    exit "$status"
                fi
                ;;
        esac
    done
}

run_hooks init.d

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

run_hooks pre-start.d

exec /usr/local/bin/graphit-broker "$@"
