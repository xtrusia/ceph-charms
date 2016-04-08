
#
# Copyright 2012 Canonical Ltd.
#
# Authors:
#  James Page <james.page@ubuntu.com>
#  Paul Collins <paul.collins@canonical.com>
#

import socket
import re
from charmhelpers.core.hookenv import (
    unit_get,
    cached,
    config,
)
from charmhelpers.core import unitdata
from charmhelpers.fetch import (
    apt_install,
    filter_installed_packages
)

from charmhelpers.core.host import (
    lsb_release
)

from charmhelpers.contrib.network.ip import (
    get_address_in_network,
    get_ipv6_addr
)

TEMPLATES_DIR = 'templates'

try:
    import jinja2
except ImportError:
    apt_install(filter_installed_packages(['python-jinja2']),
                fatal=True)
    import jinja2

try:
    import dns.resolver
except ImportError:
    apt_install(filter_installed_packages(['python-dnspython']),
                fatal=True)
    import dns.resolver


def render_template(template_name, context, template_dir=TEMPLATES_DIR):
    templates = jinja2.Environment(
        loader=jinja2.FileSystemLoader(template_dir))
    template = templates.get_template(template_name)
    return template.render(context)


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


def assert_charm_supports_ipv6():
    """Check whether we are able to support charms ipv6."""
    if lsb_release()['DISTRIB_CODENAME'].lower() < "trusty":
        raise Exception("IPv6 is not supported in the charms for Ubuntu "
                        "versions less than Trusty 14.04")


# copied charmhelpers.contrib.openstack.utils so that the charm does need the
# entire set of dependencies that that module actually also has to bring in
# from charmhelpers.
def set_unit_paused():
    """Set the unit to a paused state in the local kv() store.
    This does NOT actually pause the unit
    """
    with unitdata.HookData()() as t:
        kv = t[0]
        kv.set('unit-paused', True)


def clear_unit_paused():
    """Clear the unit from a paused state in the local kv() store
    This does NOT actually restart any services - it only clears the
    local state.
    """
    with unitdata.HookData()() as t:
        kv = t[0]
        kv.set('unit-paused', False)


def is_unit_paused_set():
    """Return the state of the kv().get('unit-paused').
    This does NOT verify that the unit really is paused.

    To help with units that don't have HookData() (testing)
    if it excepts, return False
    """
    try:
        with unitdata.HookData()() as t:
            kv = t[0]
            # transform something truth-y into a Boolean.
            return not(not(kv.get('unit-paused')))
    except:
        return False
