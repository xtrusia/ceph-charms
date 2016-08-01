#!/usr/bin/python
#
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
import os
import random
import subprocess
import sys
import tempfile
import socket
import time
import netifaces

sys.path.append('lib')
from ceph.ceph import ceph
from charmhelpers.core import hookenv
from charmhelpers.core.hookenv import (
    log,
    ERROR,
    DEBUG,
    config,
    relation_ids,
    related_units,
    relation_get,
    Hooks,
    UnregisteredHookError,
    service_name,
    status_set,
    storage_get,
    storage_list,
)
from charmhelpers.core.host import (
    umount,
    mkdir,
    cmp_pkgrevno,
    service_stop,
    service_start,
    chownr)
from charmhelpers.fetch import (
    add_source,
    apt_install,
    apt_update,
    filter_installed_packages,
)
from charmhelpers.core.sysctl import create as create_sysctl
from charmhelpers.core import host

from utils import (
    get_host_ip,
    get_networks,
    assert_charm_supports_ipv6,
    render_template,
    is_unit_paused_set,
    get_public_addr,
    get_cluster_addr,
)

from charmhelpers.contrib.openstack.alternatives import install_alternative
from charmhelpers.contrib.network.ip import (
    get_ipv6_addr,
    format_ipv6_addr,
)
from charmhelpers.contrib.storage.linux.ceph import (
    CephConfContext,
    monitor_key_set,
    monitor_key_exists,
    monitor_key_get)
from charmhelpers.contrib.charmsupport import nrpe
from charmhelpers.contrib.hardening.harden import harden

hooks = Hooks()

# A dict of valid ceph upgrade paths.  Mapping is old -> new
upgrade_paths = {
    'cloud:trusty-juno': 'cloud:trusty-kilo',
    'cloud:trusty-kilo': 'cloud:trusty-liberty',
    'cloud:trusty-liberty': 'cloud:trusty-mitaka',
}


def pretty_print_upgrade_paths():
    lines = []
    for key, value in upgrade_paths.iteritems():
        lines.append("{} -> {}".format(key, value))
    return lines


def check_for_upgrade():
    release_info = host.lsb_release()
    if not release_info['DISTRIB_CODENAME'] == 'trusty':
        log("Invalid upgrade path from {}.  Only trusty is currently "
            "supported".format(release_info['DISTRIB_CODENAME']))
        return

    c = hookenv.config()
    old_version = c.previous('source')
    log('old_version: {}'.format(old_version))
    # Strip all whitespace
    new_version = hookenv.config('source')
    if new_version:
        # replace all whitespace
        new_version = new_version.replace(' ', '')
    log('new_version: {}'.format(new_version))

    if old_version in upgrade_paths:
        if new_version == upgrade_paths[old_version]:
            log("{} to {} is a valid upgrade path.  Proceeding.".format(
                old_version, new_version))
            roll_osd_cluster(new_version)
        else:
            # Log a helpful error message
            log("Invalid upgrade path from {} to {}.  "
                "Valid paths are: {}".format(old_version,
                                             new_version,
                                             pretty_print_upgrade_paths()))


def lock_and_roll(my_name):
    start_timestamp = time.time()

    log('monitor_key_set {}_start {}'.format(my_name, start_timestamp))
    monitor_key_set('osd-upgrade', "{}_start".format(my_name), start_timestamp)
    log("Rolling")
    # This should be quick
    upgrade_osd()
    log("Done")

    stop_timestamp = time.time()
    # Set a key to inform others I am finished
    log('monitor_key_set {}_done {}'.format(my_name, stop_timestamp))
    monitor_key_set('osd-upgrade', "{}_done".format(my_name), stop_timestamp)


def wait_on_previous_node(previous_node):
    log("Previous node is: {}".format(previous_node))

    previous_node_finished = monitor_key_exists(
        'osd-upgrade',
        "{}_done".format(previous_node))

    while previous_node_finished is False:
        log("{} is not finished. Waiting".format(previous_node))
        # Has this node been trying to upgrade for longer than
        # 10 minutes?
        # If so then move on and consider that node dead.

        # NOTE: This assumes the clusters clocks are somewhat accurate
        # If the hosts clock is really far off it may cause it to skip
        # the previous node even though it shouldn't.
        current_timestamp = time.time()
        previous_node_start_time = monitor_key_get(
            'osd-upgrade',
            "{}_start".format(previous_node))
        if (current_timestamp - (10 * 60)) > previous_node_start_time:
            # Previous node is probably dead.  Lets move on
            if previous_node_start_time is not None:
                log(
                    "Waited 10 mins on node {}. current time: {} > "
                    "previous node start time: {} Moving on".format(
                        previous_node,
                        (current_timestamp - (10 * 60)),
                        previous_node_start_time))
                return
        else:
            # I have to wait.  Sleep a random amount of time and then
            # check if I can lock,upgrade and roll.
            wait_time = random.randrange(5, 30)
            log('waiting for {} seconds'.format(wait_time))
            time.sleep(wait_time)
            previous_node_finished = monitor_key_exists(
                'osd-upgrade',
                "{}_done".format(previous_node))


def get_upgrade_position(osd_sorted_list, match_name):
    for index, item in enumerate(osd_sorted_list):
        if item.name == match_name:
            return index
    return None


# Edge cases:
# 1. Previous node dies on upgrade, can we retry?
# 2. This assumes that the osd failure domain is not set to osd.
#    It rolls an entire server at a time.
def roll_osd_cluster(new_version):
    """
    This is tricky to get right so here's what we're going to do.
    There's 2 possible cases: Either I'm first in line or not.
    If I'm not first in line I'll wait a random time between 5-30 seconds
    and test to see if the previous osd is upgraded yet.

    TODO: If you're not in the same failure domain it's safe to upgrade
     1. Examine all pools and adopt the most strict failure domain policy
        Example: Pool 1: Failure domain = rack
        Pool 2: Failure domain = host
        Pool 3: Failure domain = row

        outcome: Failure domain = host
    """
    log('roll_osd_cluster called with {}'.format(new_version))
    my_name = socket.gethostname()
    osd_tree = ceph.get_osd_tree(service='osd-upgrade')
    # A sorted list of osd unit names
    osd_sorted_list = sorted(osd_tree)
    log("osd_sorted_list: {}".format(osd_sorted_list))

    try:
        position = get_upgrade_position(osd_sorted_list, my_name)
        log("upgrade position: {}".format(position))
        if position == 0:
            # I'm first!  Roll
            # First set a key to inform others I'm about to roll
            lock_and_roll(my_name=my_name)
        else:
            # Check if the previous node has finished
            status_set('blocked',
                       'Waiting on {} to finish upgrading'.format(
                           osd_sorted_list[position - 1].name))
            wait_on_previous_node(
                previous_node=osd_sorted_list[position - 1].name)
            lock_and_roll(my_name=my_name)
    except ValueError:
        log("Failed to find name {} in list {}".format(
            my_name, osd_sorted_list))
        status_set('blocked', 'failed to upgrade osd')


def upgrade_osd():
    current_version = ceph.get_version()
    status_set("maintenance", "Upgrading osd")
    log("Current ceph version is {}".format(current_version))
    new_version = config('release-version')
    log("Upgrading to: {}".format(new_version))

    try:
        add_source(config('source'), config('key'))
        apt_update(fatal=True)
    except subprocess.CalledProcessError as err:
        log("Adding the ceph source failed with message: {}".format(
            err.message))
        status_set("blocked", "Upgrade to {} failed".format(new_version))
        sys.exit(1)
    try:
        if ceph.systemd():
            for osd_id in ceph.get_local_osd_ids():
                service_stop('ceph-osd@{}'.format(osd_id))
        else:
            service_stop('ceph-osd-all')
        apt_install(packages=ceph.PACKAGES, fatal=True)

        # Ensure the ownership of Ceph's directories is correct
        chownr(path=os.path.join(os.sep, "var", "lib", "ceph"),
               owner=ceph.ceph_user(),
               group=ceph.ceph_user())
        if ceph.systemd():
            for osd_id in ceph.get_local_osd_ids():
                service_start('ceph-osd@{}'.format(osd_id))
        else:
            service_start('ceph-osd-all')
    except subprocess.CalledProcessError as err:
        log("Stopping ceph and upgrading packages failed "
            "with message: {}".format(err.message))
        status_set("blocked", "Upgrade to {} failed".format(new_version))
        sys.exit(1)


def tune_network_adapters():
    interfaces = netifaces.interfaces()
    for interface in interfaces:
        if interface == "lo":
            # Skip the loopback
            continue
        log("Looking up {} for possible sysctl tuning.".format(interface))
        ceph.tune_nic(interface)


@hooks.hook('install.real')
@harden()
def install():
    add_source(config('source'), config('key'))
    apt_update(fatal=True)
    apt_install(packages=ceph.PACKAGES, fatal=True)
    if config('autotune'):
        tune_network_adapters()


def az_info():
    az_info = os.environ.get('JUJU_AVAILABILITY_ZONE')
    log("AZ Info: " + az_info)
    return az_info


def use_short_objects():
    '''
    Determine whether OSD's should be configured with
    limited object name lengths.

    @return: boolean indicating whether OSD's should be limited
    '''
    if cmp_pkgrevno('ceph', "10.2.0") >= 0:
        if config('osd-format') in ('ext4'):
            return True
        for device in config('osd-devices'):
            if not device.startswith('/dev'):
                # TODO: determine format of directory based
                #       OSD location
                return True
    return False


def get_ceph_context():
    mon_hosts = get_mon_hosts()
    log('Monitor hosts are ' + repr(mon_hosts))

    networks = get_networks('ceph-public-network')
    public_network = ', '.join(networks)

    networks = get_networks('ceph-cluster-network')
    cluster_network = ', '.join(networks)

    cephcontext = {
        'auth_supported': get_auth(),
        'mon_hosts': ' '.join(mon_hosts),
        'fsid': get_fsid(),
        'old_auth': cmp_pkgrevno('ceph', "0.51") < 0,
        'osd_journal_size': config('osd-journal-size'),
        'use_syslog': str(config('use-syslog')).lower(),
        'ceph_public_network': public_network,
        'ceph_cluster_network': cluster_network,
        'loglevel': config('loglevel'),
        'dio': str(config('use-direct-io')).lower(),
        'short_object_len': use_short_objects(),
    }

    if config('prefer-ipv6'):
        dynamic_ipv6_address = get_ipv6_addr()[0]
        if not public_network:
            cephcontext['public_addr'] = dynamic_ipv6_address
        if not cluster_network:
            cephcontext['cluster_addr'] = dynamic_ipv6_address
    else:
        cephcontext['public_addr'] = get_public_addr()
        cephcontext['cluster_addr'] = get_cluster_addr()

    if config('customize-failure-domain'):
        if az_info():
            cephcontext['crush_location'] = "root=default rack={} host={}" \
                .format(az_info(), socket.gethostname())
        else:
            log(
                "Your Juju environment doesn't"
                "have support for Availability Zones"
            )

    # NOTE(dosaboy): these sections must correspond to what is supported in the
    #                config template.
    sections = ['global', 'osd']
    cephcontext.update(CephConfContext(permitted_sections=sections)())
    return cephcontext


def emit_cephconf():
    # Install ceph.conf as an alternative to support
    # co-existence with other charms that write this file
    charm_ceph_conf = "/var/lib/charm/{}/ceph.conf".format(service_name())
    mkdir(os.path.dirname(charm_ceph_conf), owner=ceph.ceph_user(),
          group=ceph.ceph_user())
    with open(charm_ceph_conf, 'w') as cephconf:
        cephconf.write(render_template('ceph.conf', get_ceph_context()))
    install_alternative('ceph.conf', '/etc/ceph/ceph.conf',
                        charm_ceph_conf, 90)


JOURNAL_ZAPPED = '/var/lib/ceph/journal_zapped'


def read_zapped_journals():
    if os.path.exists(JOURNAL_ZAPPED):
        with open(JOURNAL_ZAPPED) as zapfile:
            zapped = set(
                filter(None,
                       [l.strip() for l in zapfile.readlines()]))
            log("read zapped: {}".format(zapped), level=DEBUG)
            return zapped
    return set()


def write_zapped_journals(journal_devs):
    tmpfh, tmpfile = tempfile.mkstemp()
    with os.fdopen(tmpfh, 'wb') as zapfile:
        log("write zapped: {}".format(journal_devs),
            level=DEBUG)
        zapfile.write('\n'.join(sorted(list(journal_devs))))
    os.rename(tmpfile, JOURNAL_ZAPPED)


def check_overlap(journaldevs, datadevs):
    if not journaldevs.isdisjoint(datadevs):
        msg = ("Journal/data devices mustn't"
               " overlap; journal: {0}, data: {1}".format(journaldevs,
                                                          datadevs))
        log(msg, level=ERROR)
        raise ValueError(msg)


@hooks.hook('config-changed')
@harden()
def config_changed():
    # Check if an upgrade was requested
    check_for_upgrade()

    # Pre-flight checks
    if config('osd-format') not in ceph.DISK_FORMATS:
        log('Invalid OSD disk format configuration specified', level=ERROR)
        sys.exit(1)

    if config('prefer-ipv6'):
        assert_charm_supports_ipv6()

    sysctl_dict = config('sysctl')
    if sysctl_dict:
        create_sysctl(sysctl_dict, '/etc/sysctl.d/50-ceph-osd-charm.conf')

    e_mountpoint = config('ephemeral-unmount')
    if e_mountpoint and ceph.filesystem_mounted(e_mountpoint):
        umount(e_mountpoint)
    prepare_disks_and_activate()


@hooks.hook('storage.real')
def prepare_disks_and_activate():
    osd_journal = get_journal_devices()
    check_overlap(osd_journal, set(get_devices()))
    log("got journal devs: {}".format(osd_journal), level=DEBUG)
    already_zapped = read_zapped_journals()
    non_zapped = osd_journal - already_zapped
    for journ in non_zapped:
        ceph.maybe_zap_journal(journ)
    write_zapped_journals(osd_journal)

    if ceph.is_bootstrapped():
        log('ceph bootstrapped, rescanning disks')
        emit_cephconf()
        for dev in get_devices():
            ceph.osdize(dev, config('osd-format'),
                        osd_journal, config('osd-reformat'),
                        config('ignore-device-errors'),
                        config('osd-encrypt'))
            # Make it fast!
            if config('autotune'):
                ceph.tune_dev(dev)
        ceph.start_osds(get_devices())


def get_mon_hosts():
    hosts = []
    for relid in relation_ids('mon'):
        for unit in related_units(relid):
            addr = \
                relation_get('ceph-public-address',
                             unit,
                             relid) or get_host_ip(
                    relation_get(
                        'private-address',
                        unit,
                        relid))

            if addr:
                hosts.append('{}:6789'.format(format_ipv6_addr(addr) or addr))

    hosts.sort()
    return hosts


def get_fsid():
    return get_conf('fsid')


def get_auth():
    return get_conf('auth')


def get_conf(name):
    for relid in relation_ids('mon'):
        for unit in related_units(relid):
            conf = relation_get(name,
                                unit, relid)
            if conf:
                return conf
    return None


def reformat_osd():
    if config('osd-reformat'):
        return True
    else:
        return False


def get_devices():
    if config('osd-devices'):
        devices = [
            os.path.realpath(path)
            for path in config('osd-devices').split(' ')]
    else:
        devices = []

    # List storage instances for the 'osd-devices'
    # store declared for this charm too, and add
    # their block device paths to the list.
    storage_ids = storage_list('osd-devices')
    devices.extend((storage_get('location', s) for s in storage_ids))
    return devices


def get_journal_devices():
    if config('osd-journal'):
        devices = config('osd-journal')
        devices = [l.strip() for l in config('osd-journal').split(' ')]
    else:
        devices = []
    storage_ids = storage_list('osd-journals')
    devices.extend((storage_get('location', s) for s in storage_ids))
    devices = filter(os.path.exists, devices)

    return set(devices)


@hooks.hook('mon-relation-changed',
            'mon-relation-departed')
def mon_relation():
    bootstrap_key = relation_get('osd_bootstrap_key')
    upgrade_key = relation_get('osd_upgrade_key')
    if get_fsid() and get_auth() and bootstrap_key:
        log('mon has provided conf- scanning disks')
        emit_cephconf()
        ceph.import_osd_bootstrap_key(bootstrap_key)
        ceph.import_osd_upgrade_key(upgrade_key)
        prepare_disks_and_activate()
    else:
        log('mon cluster has not yet provided conf')


@hooks.hook('upgrade-charm')
@harden()
def upgrade_charm():
    if get_fsid() and get_auth():
        emit_cephconf()
    apt_install(packages=filter_installed_packages(ceph.PACKAGES),
                fatal=True)


@hooks.hook('nrpe-external-master-relation-joined',
            'nrpe-external-master-relation-changed')
def update_nrpe_config():
    # python-dbus is used by check_upstart_job
    apt_install('python-dbus')
    hostname = nrpe.get_nagios_hostname()
    current_unit = nrpe.get_nagios_unit_name()
    nrpe_setup = nrpe.NRPE(hostname=hostname)
    nrpe_setup.add_check(
        shortname='ceph-osd',
        description='process check {%s}' % current_unit,
        check_cmd=('/bin/cat /var/lib/ceph/osd/ceph-*/whoami |'
                   'xargs -I@ status ceph-osd id=@ && exit 0 || exit 2')
    )
    nrpe_setup.write()


def assess_status():
    """Assess status of current unit"""
    # check to see if the unit is paused.
    if is_unit_paused_set():
        status_set('maintenance',
                   "Paused. Use 'resume' action to resume normal service.")
        return
    # Check for mon relation
    if len(relation_ids('mon')) < 1:
        status_set('blocked', 'Missing relation: monitor')
        return

    # Check for monitors with presented addresses
    # Check for bootstrap key presentation
    monitors = get_mon_hosts()
    if len(monitors) < 1 or not get_conf('osd_bootstrap_key'):
        status_set('waiting', 'Incomplete relation: monitor')
        return

    # Check for OSD device creation parity i.e. at least some devices
    # must have been presented and used for this charm to be operational
    running_osds = ceph.get_running_osds()
    if not running_osds:
        status_set('blocked',
                   'No block devices detected using current configuration')
    else:
        status_set('active',
                   'Unit is ready ({} OSD)'.format(len(running_osds)))


@hooks.hook('update-status')
@harden()
def update_status():
    log('Updating status.')


if __name__ == '__main__':
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log('Unknown hook {} - skipping.'.format(e))
    assess_status()
