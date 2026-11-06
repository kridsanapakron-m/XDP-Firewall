#!/bin/bash

CMD_DIR=$(realpath "$(dirname "${BASH_SOURCE[0]}")")
[ -n "${PERF_DIR:-}" ] || source "$CMD_DIR/../perf_env.sh"
ssh_options=${ssh_options:-"-o BatchMode=yes -o ConnectTimeout=5 -o ControlMaster=auto -o ControlPersist=10m \
-o ControlPath=/tmp/perf-ssh-%r@%h:%p"}

remote() {
    case $1 in
        a) bash -s <<< ". $CMD_DIR/../perf_env.sh; $2" ;;
        b) ssh $ssh_options $SSH_LB bash -s <<< ". $PERF_DIR/perf_env.sh; $2" ;;
        c) ssh $ssh_options $SSH_SERVER bash -s <<< ". $PERF_DIR/perf_env.sh; $2" ;;
        *) echo "เครื่องต้องเป็น a b หรือ c" >&2; return 2 ;;
    esac
}

cmd() {
    local output
    CMD_STATUS=0
    output=$(remote "$1" "$2") || CMD_STATUS=$?
    {
        echo "  ${1^^}\$ $2"
        if [ -n "$output" ]; then sed 's/^/     /' <<< "$output"; fi
        if [ $CMD_STATUS != 0 ]; then echo "     (exit $CMD_STATUS)"; fi
    } >&2
    if [ -n "$output" ]; then echo "$output"; fi
}

if [ "$0" = "${BASH_SOURCE[0]}" ]; then
    if [ $# != 2 ]; then echo "ใช้: $0 <a|b|c> '<คำสั่ง>'"; exit 1; fi
    cmd "$1" "$2" >/dev/null
    exit $CMD_STATUS
fi
