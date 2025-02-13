#!/usr/bin/env bash

function cleaript() {
    # Docker can inject rules causing firewall conflicts
    sudo iptables -P FORWARD ACCEPT  || true
    sudo ip6tables -P FORWARD ACCEPT || true
    sudo iptables -F FORWARD  || true
    sudo ip6tables -F FORWARD || true

}

function cacheimgs() {
    local base="${1?missing}"
    juju add-machine --base "$base"
    sleep 10
    juju add-machine --base "$base" --constraints "virt-type=virtual-machine" 
    while [ "$(juju machines | egrep -wc 'started')" -ne 2 ]; do
        sleep 2
    done
    juju machines | awk '/started/{ print $1 }' | while read n; do juju remove-machine --force --no-prompt $n ; done
    sleep 5
}

run="${1}"
shift

$run "$@"
