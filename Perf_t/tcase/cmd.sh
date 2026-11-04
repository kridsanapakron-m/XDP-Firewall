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

field() { awk -v k="$1" '{ gsub(/[=:]/, " "); for (i = 1; i < NF; i++) if ($i == k) { print $(i + 1); exit } }'; }

delta() {
    awk -v l="$1" -v a="$2" -v b="$3" 'BEGIN {
        n = a ~ /^-?[0-9]+$/ && b ~ /^-?[0-9]+$/
        printf "  %-30s %16s → %-16s Δ %s\n", l, a == "" ? "-" : a, b == "" ? "-" : b, n ? sprintf("%.0f", b - a) : "-" }'
}

delta_field() { delta "$1" "$(field $2 <<< "$3")" "$(field $2 <<< "$4")"; }

ratio() {
    awk -v l="$1" -v a0="$2" -v a1="$3" -v b0="$4" -v b1="$5" 'BEGIN {
        ok = a0 ~ /^[0-9]+$/ && a1 ~ /^[0-9]+$/ && b0 ~ /^[0-9]+$/ && b1 ~ /^[0-9]+$/ && b1 - b0 > 0
        printf "  %-30s %s\n", l, ok ? sprintf("%.1f", (a1 - a0) / (b1 - b0)) : "-" }'
}

if [ "$0" = "${BASH_SOURCE[0]}" ]; then
    if [ $# != 2 ]; then echo "ใช้: $0 <a|b|c> '<คำสั่ง>'"; exit 1; fi
    cmd "$1" "$2" >/dev/null
    exit $CMD_STATUS
fi
