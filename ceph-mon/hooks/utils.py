# Copyright 2016 Canonical Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import re
import socket
import subprocess

from charmhelpers.core.hookenv import (
    DEBUG,
    cached,
    config,
    goal_state,
    log,
    network_get_primary_address,
    related_units,
    relation_ids,
    status_set,
    unit_get,
)
from charmhelpers.fetch import (
    apt_install,
    filter_installed_packages
)
from charmhelpers.core.host import (
    lsb_release,
    CompareHostReleases,
)
from charmhelpers.contrib.network.ip import (
    get_address_in_network,
    get_ipv6_addr
)

try:
    import dns.resolver
except ImportError:
    apt_install(filter_installed_packages(['python-dnspython']),
                fatal=True)
    import dns.resolver


def enable_pocket(pocket):
    apt_sources = "/etc/apt/sources.list"
    with open(apt_sources, "r") as sources:
        lines = sources.readlines()
    with open(apt_sources, "w") as sources:
        for line in lines:
            if pocket in line:
                sources.write(re.sub('^# deb', 'deb', line))
            else:
                sources.write(line)


@cached
def get_unit_hostname():
    return socket.gethostname()


@cached
def get_host_ip(hostname=None):
    if config('prefer-ipv6'):
        return get_ipv6_addr()[0]

    hostname = hostname or unit_get('private-address')
    try:
        # Test to see if already an IPv4 address
        socket.inet_aton(hostname)
        return hostname
    except socket.error:
        # This may throw an NXDOMAIN exception; in which case
        # things are badly broken so just let it kill the hook
        answers = dns.resolver.query(hostname, 'A')
        if answers:
            return answers[0].address


@cached
def get_public_addr():
    if config('ceph-public-network'):
        return get_network_addrs('ceph-public-network')[0]

    try:
        return network_get_primary_address('public')
    except NotImplementedError:
        log("network-get not supported", DEBUG)

    return get_host_ip()


@cached
def get_cluster_addr():
    if config('ceph-cluster-network'):
        return get_network_addrs('ceph-cluster-network')[0]

    try:
        return network_get_primary_address('cluster')
    except NotImplementedError:
        log("network-get not supported", DEBUG)

    return get_host_ip()


def get_networks(config_opt='ceph-public-network'):
    """Get all configured networks from provided config option.

    If public network(s) are provided, go through them and return those for
    which we have an address configured.
    """
    networks = config(config_opt)
    if networks:
        networks = networks.split()
        return [n for n in networks if get_address_in_network(n)]

    return []


def get_network_addrs(config_opt):
    """Get all configured public networks addresses.

    If public network(s) are provided, go through them and return the
    addresses we have configured on any of those networks.
    """
    addrs = []
    networks = config(config_opt)
    if networks:
        networks = networks.split()
        addrs = [get_address_in_network(n) for n in networks]
        addrs = [a for a in addrs if a]

    if not addrs:
        if networks:
            msg = ("Could not find an address on any of '%s' - resolve this "
                   "error to retry" % (networks))
            status_set('blocked', msg)
            raise Exception(msg)
        else:
            return [get_host_ip()]

    return addrs


def assert_charm_supports_ipv6():
    """Check whether we are able to support charms ipv6."""
    _release = lsb_release()['DISTRIB_CODENAME'].lower()
    if CompareHostReleases(_release) < "trusty":
        raise Exception("IPv6 is not supported in the charms for Ubuntu "
                        "versions less than Trusty 14.04")


def has_rbd_mirrors():
    """Determine if we have or will have ``rbd-mirror`` charms related.

    :returns: True or False
    :rtype: bool
    """
    try:
        # NOTE(fnordahl): This optimization will not be useful until we get a
        # resolution on LP: #1818245
        raise NotImplementedError
        gs = goal_state()
        return 'rbd-mirror' in gs.get('relations', {})
    except NotImplementedError:
        for relid in relation_ids('rbd-mirror'):
            if related_units(relid):
                return True


def get_default_rbd_features():
    """Get default value for ``rbd_default_features``.

    This is retrieved by asking the installed Ceph binary to show its runtime
    config when using a empty configuration file.

    :returns: Installed Ceph's Default vaule for ``rbd_default_features``
    :rtype: int
    :raises: subprocess.CalledProcessError
    """
    output = subprocess.check_output(
        ['ceph', '-c', '/dev/null', '--show-config'],
        universal_newlines=True)
    for line in output.splitlines():
        if 'rbd_default_features' in line:
            return int(line.split('=')[1].lstrip().rstrip())


def get_rbd_features():
    """Determine if we should set, and what the rbd default features should be.

    :returns: None or the apropriate value to use
    :rtype: Option[int, None]
    """
    RBD_FEATURE_EXCLUSIVE_LOCK = 4
    RBD_FEATURE_JOURNALING = 64

    rbd_feature_config = config('default-rbd-features')
    if rbd_feature_config:
        return int(rbd_feature_config)
    elif has_rbd_mirrors():
        return (get_default_rbd_features() |
                RBD_FEATURE_EXCLUSIVE_LOCK | RBD_FEATURE_JOURNALING)
