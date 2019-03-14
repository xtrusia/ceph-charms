#!/usr/bin/env python3
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

import json
import os
import subprocess
import socket
import sys
import uuid

sys.path.append('lib')
import ceph.utils as ceph
from ceph.broker import (
    process_requests
)

from charmhelpers.core import hookenv
from charmhelpers.core.hookenv import (
    log,
    DEBUG,
    ERROR,
    INFO,
    config,
    relation_ids,
    related_units,
    is_relation_made,
    relation_get,
    relation_set,
    leader_set, leader_get,
    is_leader,
    remote_unit,
    Hooks, UnregisteredHookError,
    service_name,
    relations_of_type,
    status_set,
    local_unit,
    application_version_set)
from charmhelpers.core.host import (
    service_pause,
    service_restart,
    mkdir,
    write_file,
    rsync,
    cmp_pkgrevno)
from charmhelpers.fetch import (
    apt_install,
    apt_update,
    filter_installed_packages,
    add_source,
    get_upstream_version,
)
from charmhelpers.payload.execd import execd_preinstall
from charmhelpers.contrib.openstack.alternatives import install_alternative
from charmhelpers.contrib.openstack.utils import (
    clear_unit_paused,
    clear_unit_upgrading,
    get_os_codename_install_source,
    is_unit_upgrading_set,
    set_unit_paused,
    set_unit_upgrading,
)
from charmhelpers.contrib.network.ip import (
    get_ipv6_addr,
    format_ipv6_addr,
)
from charmhelpers.core.sysctl import create as create_sysctl
from charmhelpers.core.templating import render
from charmhelpers.contrib.storage.linux.ceph import (
    CephConfContext)
from utils import (
    add_rbd_mirror_features,
    assert_charm_supports_ipv6,
    get_cluster_addr,
    get_networks,
    get_public_addr,
    get_rbd_features,
    has_rbd_mirrors,
)

from charmhelpers.contrib.charmsupport import nrpe
from charmhelpers.contrib.hardening.harden import harden

hooks = Hooks()

NAGIOS_PLUGINS = '/usr/local/lib/nagios/plugins'
SCRIPTS_DIR = '/usr/local/bin'
STATUS_FILE = '/var/lib/nagios/cat-ceph-status.txt'
STATUS_CRONFILE = '/etc/cron.d/cat-ceph-health'


def check_for_upgrade():
    if not ceph.is_bootstrapped():
        log("Ceph is not bootstrapped, skipping upgrade checks.")
        return

    c = hookenv.config()
    old_version = ceph.resolve_ceph_version(c.previous('source') or
                                            'distro')
    log('old_version: {}'.format(old_version))
    # Strip all whitespace
    new_version = ceph.resolve_ceph_version(hookenv.config('source'))

    old_version_os = get_os_codename_install_source(c.previous('source') or
                                                    'distro')
    new_version_os = get_os_codename_install_source(hookenv.config('source'))

    log('new_version: {}'.format(new_version))

    if (old_version in ceph.UPGRADE_PATHS and
            new_version == ceph.UPGRADE_PATHS[old_version]):
        log("{} to {} is a valid upgrade path.  Proceeding.".format(
            old_version, new_version))
        ceph.roll_monitor_cluster(new_version=new_version,
                                  upgrade_key='admin')
    elif (old_version == new_version and
          old_version_os < new_version_os):
        # See LP: #1778823
        add_source(hookenv.config('source'), hookenv.config('key'))
        log(("The installation source has changed yet there is no new major "
             "version of Ceph in this new source. As a result no package "
             "upgrade will take effect. Please upgrade manually if you need "
             "to."), level=INFO)
    else:
        # Log a helpful error message
        log("Invalid upgrade path from {} to {}.  "
            "Valid paths are: {}".format(old_version,
                                         new_version,
                                         ceph.pretty_print_upgrade_paths()),
            level=ERROR)


@hooks.hook('install.real')
@harden()
def install():
    execd_preinstall()
    add_source(config('source'), config('key'))
    apt_update(fatal=True)
    apt_install(packages=ceph.determine_packages(), fatal=True)
    try:
        # we defer and explicitly run `ceph-create-keys` from
        # add_keyring_to_ceph() as part of bootstrap process
        # LP: #1719436.
        service_pause('ceph-create-keys')
    except ValueError:
        pass


def get_ceph_context():
    networks = get_networks('ceph-public-network')
    public_network = ', '.join(networks)

    networks = get_networks('ceph-cluster-network')
    cluster_network = ', '.join(networks)

    cephcontext = {
        'auth_supported': config('auth-supported'),
        'mon_hosts': config('monitor-hosts') or ' '.join(get_mon_hosts()),
        'fsid': leader_get('fsid'),
        'old_auth': cmp_pkgrevno('ceph', "0.51") < 0,
        'use_syslog': str(config('use-syslog')).lower(),
        'ceph_public_network': public_network,
        'ceph_cluster_network': cluster_network,
        'loglevel': config('loglevel'),
        'dio': str(config('use-direct-io')).lower(),
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

    rbd_features = get_rbd_features()
    if rbd_features:
        cephcontext['rbd_features'] = rbd_features

    if config('disable-pg-max-object-skew'):
        cephcontext['disable_object_skew'] = config(
            'disable-pg-max-object-skew')

    # NOTE(dosaboy): these sections must correspond to what is supported in the
    #                config template.
    sections = ['global', 'mds', 'mon']
    cephcontext.update(CephConfContext(permitted_sections=sections)())
    return cephcontext


def emit_cephconf():
    # Install ceph.conf as an alternative to support
    # co-existence with other charms that write this file
    charm_ceph_conf = "/var/lib/charm/{}/ceph.conf".format(service_name())
    mkdir(os.path.dirname(charm_ceph_conf), owner=ceph.ceph_user(),
          group=ceph.ceph_user())
    render('ceph.conf', charm_ceph_conf, get_ceph_context(), perms=0o644)
    install_alternative('ceph.conf', '/etc/ceph/ceph.conf',
                        charm_ceph_conf, 100)


JOURNAL_ZAPPED = '/var/lib/ceph/journal_zapped'


@hooks.hook('config-changed')
@harden()
def config_changed():
    # Get the cfg object so we can see if the no-bootstrap value has changed
    # and triggered this hook invocation
    cfg = config()
    if config('prefer-ipv6'):
        assert_charm_supports_ipv6()

    check_for_upgrade()

    log('Monitor hosts are ' + repr(get_mon_hosts()))

    sysctl_dict = config('sysctl')
    if sysctl_dict:
        create_sysctl(sysctl_dict, '/etc/sysctl.d/50-ceph-charm.conf')
    if relations_of_type('nrpe-external-master'):
        update_nrpe_config()

    if is_leader():
        if not config('no-bootstrap'):
            if not leader_get('fsid') or not leader_get('monitor-secret'):
                fsid = "{}".format(uuid.uuid1())
                if config('monitor-secret'):
                    mon_secret = config('monitor-secret')
                else:
                    mon_secret = "{}".format(ceph.generate_monitor_secret())
                opts = {
                    'fsid': fsid,
                    'monitor-secret': mon_secret,
                }
                try:
                    leader_set(opts)
                    status_set('maintenance',
                               'Created FSID and Monitor Secret')
                    log("Settings for the cluster are: {}".format(opts))
                except Exception as e:
                    # we're probably not the leader an exception occured
                    # let's log it anyway.
                    log("leader_set failed: {}".format(str(e)))
        elif (cfg.changed('no-bootstrap') and
              is_relation_made('bootstrap-source')):
            # User changed the no-bootstrap config option, we're the leader,
            # and the bootstrap-source relation has been made. The charm should
            # be in a blocked state indicating that the no-bootstrap option
            # must be set. This block is invoked when the user is trying to
            # get out of that scenario by enabling no-bootstrap.
            bootstrap_source_relation_changed()
    # unconditionally verify that the fsid and monitor-secret are set now
    # otherwise we exit until a leader does this.
    if leader_get('fsid') is None or leader_get('monitor-secret') is None:
            log('still waiting for leader to setup keys')
            status_set('waiting', 'Waiting for leader to setup keys')
            return

    emit_cephconf()

    # Support use of single node ceph
    if (not ceph.is_bootstrapped() and int(config('monitor-count')) == 1 and
            is_leader()):
        status_set('maintenance', 'Bootstrapping single Ceph MON')
        # the following call raises an exception if it can't add the keyring
        try:
            ceph.bootstrap_monitor_cluster(leader_get('monitor-secret'))
        except FileNotFoundError as e:  # NOQA -- PEP8 is still PY2
            log("Couldn't bootstrap the monitor yet: {}".format(str(e)))
            return
        ceph.wait_for_bootstrap()
        if cmp_pkgrevno('ceph', '12.0.0') >= 0:
            status_set('maintenance', 'Bootstrapping single Ceph MGR')
            ceph.bootstrap_manager()

    # Update client relations
    notify_client()


def get_mon_hosts():
    hosts = []
    addr = get_public_addr()
    hosts.append('{}:6789'.format(format_ipv6_addr(addr) or addr))

    rel_ids = relation_ids('mon')
    if config('no-bootstrap'):
        rel_ids += relation_ids('bootstrap-source')

    for relid in rel_ids:
        for unit in related_units(relid):
            addr = relation_get('ceph-public-address', unit, relid)
            if addr is not None:
                hosts.append('{}:6789'.format(
                    format_ipv6_addr(addr) or addr))

    return sorted(hosts)


def get_peer_units():
    """
    Returns a dictionary of unit names from the mon peer relation with
    a flag indicating whether the unit has presented its address
    """
    units = {}
    units[local_unit()] = True
    for relid in relation_ids('mon'):
        for unit in related_units(relid):
            addr = relation_get('ceph-public-address', unit, relid)
            units[unit] = addr is not None
    return units


@hooks.hook('mon-relation-joined')
def mon_relation_joined():
    public_addr = get_public_addr()
    for relid in relation_ids('mon'):
        relation_set(relation_id=relid,
                     relation_settings={'ceph-public-address': public_addr})


@hooks.hook('bootstrap-source-relation-changed')
def bootstrap_source_relation_changed():
    """Handles relation data changes on the bootstrap-source relation.

    The bootstrap-source relation to share remote bootstrap information with
    the ceph-mon charm. This relation is used to exchange the remote
    ceph-public-addresses which are used for the mon's, the fsid, and the
    monitor-secret.
    """
    if not config('no-bootstrap'):
        status_set('blocked', 'Cannot join the bootstrap-source relation when '
                              'no-bootstrap is False')
        return

    if not is_leader():
        log('Deferring leader-setting updates to the leader unit')
        return

    curr_fsid = leader_get('fsid')
    curr_secret = leader_get('monitor-secret')
    for relid in relation_ids('bootstrap-source'):
        for unit in related_units(relid=relid):
            mon_secret = relation_get('monitor-secret', unit, relid)
            fsid = relation_get('fsid', unit, relid)

            if not (mon_secret and fsid):
                log('Relation data is not ready as the fsid or the '
                    'monitor-secret are missing from the relation: '
                    'mon_secret = {} and fsid = {} '.format(mon_secret, fsid))
                continue

            if not (curr_fsid or curr_secret):
                curr_fsid = fsid
                curr_secret = mon_secret
            else:
                # The fsids and secrets need to match or the local monitors
                # will fail to join the mon cluster. If they don't,
                # bail because something needs to be investigated.
                assert curr_fsid == fsid, \
                    "bootstrap fsid '{}' != current fsid '{}'".format(
                        fsid, curr_fsid)
                assert curr_secret == mon_secret, \
                    "bootstrap secret '{}' != current secret '{}'".format(
                        mon_secret, curr_secret)
            opts = {
                'fsid': fsid,
                'monitor-secret': mon_secret,
            }
            try:
                leader_set(opts)
                log('Updating leader settings for fsid and monitor-secret '
                    'from remote relation data: {}'.format(opts))
            except Exception as e:
                # we're probably not the leader an exception occured
                # let's log it anyway.
                log("leader_set failed: {}".format(str(e)))

    # The leader unit needs to bootstrap itself as it won't receive the
    # leader-settings-changed hook elsewhere.
    if curr_fsid:
        mon_relation()


@hooks.hook('mon-relation-departed',
            'mon-relation-changed',
            'leader-settings-changed',
            'bootstrap-source-relation-departed')
def mon_relation():
    if leader_get('monitor-secret') is None:
        log('still waiting for leader to setup keys')
        status_set('waiting', 'Waiting for leader to setup keys')
        return
    emit_cephconf()

    moncount = int(config('monitor-count'))
    if len(get_mon_hosts()) >= moncount:
        if ceph.is_bootstrapped():
            # The ceph-mon unit chosen for handling broker requests is based on
            # internal Ceph MON leadership and not Juju leadership.  To update
            # the rbd-mirror relation on all ceph-mon units after pool creation
            # the unit handling the broker request will update a nonce on the
            # mon relation.
            notify_rbd_mirrors()
        else:
            status_set('maintenance', 'Bootstrapping MON cluster')
            # the following call raises an exception
            # if it can't add the keyring
            try:
                ceph.bootstrap_monitor_cluster(leader_get('monitor-secret'))
            except FileNotFoundError as e:  # NOQA -- PEP8 is still PY2
                log("Couldn't bootstrap the monitor yet: {}".format(str(e)))
                exit(0)
            ceph.wait_for_bootstrap()
            ceph.wait_for_quorum()
            if cmp_pkgrevno('ceph', '12.0.0') >= 0:
                status_set('maintenance', 'Bootstrapping Ceph MGR')
                ceph.bootstrap_manager()
            # If we can and want to
            if is_leader() and config('customize-failure-domain'):
                # But only if the environment supports it
                if os.environ.get('JUJU_AVAILABILITY_ZONE'):
                    cmds = [
                        "ceph osd getcrushmap -o /tmp/crush.map",
                        "crushtool -d /tmp/crush.map| "
                        "sed 's/step chooseleaf firstn 0 type host/step "
                        "chooseleaf firstn 0 type rack/' > "
                        "/tmp/crush.decompiled",
                        "crushtool -c /tmp/crush.decompiled -o /tmp/crush.map",
                        "crushtool -i /tmp/crush.map --test",
                        "ceph osd setcrushmap -i /tmp/crush.map"
                    ]
                    for cmd in cmds:
                        try:
                            subprocess.check_call(cmd, shell=True)
                        except subprocess.CalledProcessError as e:
                            log("Failed to modify crush map:", level='error')
                            log("Cmd: {}".format(cmd), level='error')
                            log("Error: {}".format(e.output), level='error')
                            break
                else:
                    log(
                        "Your Juju environment doesn't"
                        "have support for Availability Zones"
                    )
            notify_osds()
            notify_radosgws()
            notify_client()
            notify_rbd_mirrors()
    else:
        log('Not enough mons ({}), punting.'
            .format(len(get_mon_hosts())))


def notify_osds():
    for relid in relation_ids('osd'):
        for unit in related_units(relid):
            osd_relation(relid=relid, unit=unit)


def notify_radosgws():
    for relid in relation_ids('radosgw'):
        for unit in related_units(relid):
            radosgw_relation(relid=relid, unit=unit)


def notify_rbd_mirrors():
    for relid in relation_ids('rbd-mirror'):
        for unit in related_units(relid):
            rbd_mirror_relation(relid=relid, unit=unit, recurse=False)


def notify_client():
    for relid in relation_ids('client'):
        for unit in related_units(relid):
            client_relation(relid, unit)
    for relid in relation_ids('admin'):
        admin_relation_joined(relid)
    for relid in relation_ids('mds'):
        for unit in related_units(relid):
            mds_relation_joined(relid=relid, unit=unit)


def notify_mons():
    """Update a nonce on the ``mon`` relation.

    This is useful for flagging that our peer mon units should update some of
    their client relations.

    Normally we would have handled this with leader storage, but for the Ceph
    case, the unit handling the broker requests is the Ceph MON leader and not
    necessarilly the Juju leader.

    A non-leader unit has no way of changing data in leader-storage.
    """
    nonce = uuid.uuid4()
    for relid in relation_ids('mon'):
        for unit in related_units(relid):
            relation_set(relation_id=relid,
                         relation_settings={'nonce': nonce})


def handle_broker_request(relid, unit, add_legacy_response=False,
                          recurse=True):
    """Retrieve broker request from relation, process, return response data.

    :param relid: Realtion ID
    :type relid: str
    :param unit: Remote unit name
    :type unit: str
    :param add_legacy_response: (Optional) Adds the legacy ``broker_rsp`` key
                                to the response in addition to the new way.
    :type add_legacy_response: bool
    :param recurse: Whether we should call out to update relation functions or
                    not.  Mainly used to handle recursion when called from
                    notify_rbd_mirrors()
    :type recurse: bool
    :returns: Dictionary of response data ready for use with relation_set.
    :rtype: dict
    """
    response = {}
    if not unit:
        unit = remote_unit()
    settings = relation_get(rid=relid, unit=unit)
    if 'broker_req' in settings:
        if not ceph.is_leader():
            log("Not leader - ignoring broker request", level=DEBUG)
        else:
            rsp = process_requests(settings['broker_req'])
            unit_id = unit.replace('/', '-')
            unit_response_key = 'broker-rsp-' + unit_id
            response.update({unit_response_key: rsp})
            if add_legacy_response:
                response.update({'broker_rsp': rsp})

            if relation_ids('rbd-mirror'):
                # NOTE(fnordahl): juju relation level data candidate
                # notify mons to flag that the other mon units should update
                # their ``rbd-mirror`` relations with information about new
                # pools.
                log('Notifying peers after processing broker request.',
                    level=DEBUG)
                notify_mons()

                if recurse:
                    # update ``rbd-mirror`` relations for this unit with
                    # information about new pools.
                    log('Notifying this units rbd-mirror relations after '
                        'processing broker request.', level=DEBUG)
                    notify_rbd_mirrors()

    return response


@hooks.hook('osd-relation-joined')
@hooks.hook('osd-relation-changed')
def osd_relation(relid=None, unit=None):
    if ceph.is_quorum():
        log('mon cluster in quorum - providing fsid & keys')
        public_addr = get_public_addr()
        data = {
            'fsid': leader_get('fsid'),
            'osd_bootstrap_key': ceph.get_osd_bootstrap_key(),
            'auth': config('auth-supported'),
            'ceph-public-address': public_addr,
            'osd_upgrade_key': ceph.get_named_key('osd-upgrade',
                                                  caps=ceph.osd_upgrade_caps),
        }

        data.update(handle_broker_request(relid, unit))
        relation_set(relation_id=relid,
                     relation_settings=data)

        # NOTE: radosgw key provision is gated on presence of OSD
        #       units so ensure that any deferred hooks are processed
        notify_radosgws()
        notify_client()
        notify_rbd_mirrors()
    else:
        log('mon cluster not in quorum - deferring fsid provision')


def related_osds(num_units=3):
    '''
    Determine whether there are OSD units currently related

    @param num_units: The minimum number of units required
    @return: boolean indicating whether the required number of
             units where detected.
    '''
    units = 0
    for r_id in relation_ids('osd'):
        units += len(related_units(r_id))
    if units >= num_units:
        return True
    return False


def sufficient_osds(minimum_osds=3):
    '''
    Determine if the minimum number of OSD's have been
    bootstrapped into the cluster.

    @param expected_osds: The minimum number of OSD's required
    @return: boolean indicating whether the required number of
             OSD's where detected.
    '''
    bootstrapped_osds = 0
    for r_id in relation_ids('osd'):
        for unit in related_units(r_id):
            unit_osds = relation_get(
                attribute='bootstrapped-osds',
                unit=unit, rid=r_id
            )
            if unit_osds is not None:
                bootstrapped_osds += int(unit_osds)
    if bootstrapped_osds >= minimum_osds:
        return True
    return False


def ready_for_service():
    '''
    Determine whether the Ceph cluster is ready to service
    storage traffic from clients

    @return: boolean indicating whether the Ceph cluster is
             ready for pool creation/client usage.
    '''
    if not ceph.is_quorum():
        log('mon cluster is not in quorum', level=DEBUG)
        return False
    if not sufficient_osds(config('expected-osd-count') or 3):
        log('insufficient osds bootstrapped', level=DEBUG)
        return False
    return True


@hooks.hook('radosgw-relation-changed')
@hooks.hook('radosgw-relation-joined')
def radosgw_relation(relid=None, unit=None):
    # Install radosgw for admin tools
    apt_install(packages=filter_installed_packages(['radosgw']))
    if not unit:
        unit = remote_unit()

    # NOTE: radosgw needs some usage OSD storage, so defer key
    #       provision until OSD units are detected.
    if ready_for_service():
        log('mon cluster in quorum and osds bootstrapped '
            '- providing radosgw with keys')
        public_addr = get_public_addr()
        data = {
            'fsid': leader_get('fsid'),
            'auth': config('auth-supported'),
            'ceph-public-address': public_addr,
        }
        key_name = relation_get('key_name', unit=unit, rid=relid)
        if key_name:
            # New style, per unit keys
            data['{}_key'.format(key_name)] = (
                ceph.get_radosgw_key(name=key_name)
            )
        else:
            # Old style global radosgw key
            data['radosgw_key'] = ceph.get_radosgw_key()

        data.update(handle_broker_request(relid, unit))
        relation_set(relation_id=relid, relation_settings=data)


@hooks.hook('rbd-mirror-relation-joined')
@hooks.hook('rbd-mirror-relation-changed')
def rbd_mirror_relation(relid=None, unit=None, recurse=True):
    if ready_for_service():
        log('mon cluster in quorum and osds bootstrapped '
            '- providing rbd-mirror client with keys')
        if not unit:
            unit = remote_unit()
        # handle broker requests first to get a updated pool map
        data = (handle_broker_request(relid, unit, recurse=recurse))
        data.update({
            'auth': config('auth-supported'),
            'ceph-public-address': get_public_addr(),
            'pools': json.dumps(ceph.list_pools_detail(), sort_keys=True)
        })
        cluster_addr = get_cluster_addr()
        if cluster_addr:
            data['ceph-cluster-address'] = cluster_addr
        # handle both classic and reactive Endpoint peers
        try:
            unique_id = json.loads(
                relation_get('unique_id', unit=unit, rid=relid))
        except (TypeError, json.decoder.JSONDecodeError):
            unique_id = relation_get('unique_id', unit=unit, rid=relid)
        if unique_id:
            data['{}_key'.format(unique_id)] = ceph.get_rbd_mirror_key(
                'rbd-mirror.{}'.format(unique_id))

        relation_set(relation_id=relid, relation_settings=data)


@hooks.hook('mds-relation-changed')
@hooks.hook('mds-relation-joined')
def mds_relation_joined(relid=None, unit=None):
    if ready_for_service():
        log('mon cluster in quorum and osds bootstrapped '
            '- providing mds client with keys')
        mds_name = relation_get(attribute='mds-name',
                                rid=relid, unit=unit)
        if not unit:
            unit = remote_unit()
        public_addr = get_public_addr()
        data = {
            'fsid': leader_get('fsid'),
            '{}_mds_key'.format(mds_name):
                ceph.get_mds_key(name=mds_name),
            'auth': config('auth-supported'),
            'ceph-public-address': public_addr}
        data.update(handle_broker_request(relid, unit))
        relation_set(relation_id=relid, relation_settings=data)


@hooks.hook('admin-relation-changed')
@hooks.hook('admin-relation-joined')
def admin_relation_joined(relid=None):
    if ceph.is_quorum():
        name = relation_get('keyring-name')
        if name is None:
            name = 'admin'
        log('mon cluster in quorum - providing admin client with keys')
        mon_hosts = config('monitor-hosts') or ' '.join(get_mon_hosts())
        data = {'key': ceph.get_named_key(name=name, caps=ceph.admin_caps),
                'fsid': leader_get('fsid'),
                'auth': config('auth-supported'),
                'mon_hosts': mon_hosts,
                }
        relation_set(relation_id=relid,
                     relation_settings=data)


@hooks.hook('client-relation-changed')
@hooks.hook('client-relation-joined')
def client_relation(relid=None, unit=None):
    if ready_for_service():
        log('mon cluster in quorum and osds bootstrapped '
            '- providing client with keys, processing broker requests')
        service_name = hookenv.remote_service_name(relid=relid)
        if not service_name:
            log('Unable to determine remote service name, deferring '
                'processing of broker requests')
            return
        public_addr = get_public_addr()
        data = {'key': ceph.get_named_key(service_name),
                'auth': config('auth-supported'),
                'ceph-public-address': public_addr}
        if config('default-rbd-features'):
            data['rbd-features'] = config('default-rbd-features')
        if not unit:
            unit = remote_unit()
        data.update(
            handle_broker_request(relid, unit, add_legacy_response=True))
        relation_set(relation_id=relid,
                     relation_settings=data)


@hooks.hook('upgrade-charm.real')
@harden()
def upgrade_charm():
    emit_cephconf()
    apt_install(packages=filter_installed_packages(
        ceph.determine_packages()), fatal=True)
    try:
        # we defer and explicitly run `ceph-create-keys` from
        # add_keyring_to_ceph() as part of bootstrap process
        # LP: #1719436.
        service_pause('ceph-create-keys')
    except ValueError:
        pass
    ceph.update_monfs()
    mon_relation_joined()
    if is_relation_made("nrpe-external-master"):
        update_nrpe_config()

    # NOTE(jamespage):
    # Reprocess broker requests to ensure that any cephx
    # key permission changes are applied
    notify_client()
    notify_radosgws()
    notify_rbd_mirrors()


@hooks.hook('start')
def start():
    # In case we're being redeployed to the same machines, try
    # to make sure everything is running as soon as possible.
    if ceph.systemd():
        service_restart('ceph-mon')
    else:
        service_restart('ceph-mon-all')
    if cmp_pkgrevno('ceph', '12.0.0') >= 0:
        service_restart('ceph-mgr@{}'.format(socket.gethostname()))


@hooks.hook('nrpe-external-master-relation-joined')
@hooks.hook('nrpe-external-master-relation-changed')
def update_nrpe_config():
    # python-dbus is used by check_upstart_job
    apt_install(['python-dbus', 'lockfile-progs'])
    log('Refreshing nagios checks')
    if os.path.isdir(NAGIOS_PLUGINS):
        rsync(os.path.join(os.getenv('CHARM_DIR'), 'files', 'nagios',
                           'check_ceph_status.py'),
              os.path.join(NAGIOS_PLUGINS, 'check_ceph_status.py'))

    script = os.path.join(SCRIPTS_DIR, 'collect_ceph_status.sh')
    rsync(os.path.join(os.getenv('CHARM_DIR'), 'files',
                       'nagios', 'collect_ceph_status.sh'),
          script)
    cronjob = "{} root {}\n".format('*/5 * * * *', script)
    write_file(STATUS_CRONFILE, cronjob)

    # Find out if nrpe set nagios_hostname
    hostname = nrpe.get_nagios_hostname()
    current_unit = nrpe.get_nagios_unit_name()
    nrpe_setup = nrpe.NRPE(hostname=hostname)
    check_cmd = 'check_ceph_status.py -f {} --degraded_thresh {}' \
        ' --misplaced_thresh {}' \
        ' --recovery_rate {}'.format(STATUS_FILE,
                                     config('nagios_degraded_thresh'),
                                     config('nagios_misplaced_thresh'),
                                     config('nagios_recovery_rate'))
    if config('nagios_raise_nodeepscrub'):
        check_cmd = check_cmd + ' --raise_nodeepscrub'
    nrpe_setup.add_check(
        shortname="ceph",
        description='Check Ceph health {{{}}}'.format(current_unit),
        check_cmd=check_cmd
    )
    nrpe_setup.write()


VERSION_PACKAGE = 'ceph-common'


def assess_status():
    '''Assess status of current unit'''
    application_version_set(get_upstream_version(VERSION_PACKAGE))
    if is_unit_upgrading_set():
        status_set("blocked",
                   "Ready for do-release-upgrade and reboot. "
                   "Set complete when finished.")
        return

    # Check that the no-bootstrap config option is set in conjunction with
    # having the bootstrap-source relation established
    if not config('no-bootstrap') and is_relation_made('bootstrap-source'):
        status_set('blocked', 'Cannot join the bootstrap-source relation when '
                              'no-bootstrap is False')
        return

    moncount = int(config('monitor-count'))
    units = get_peer_units()
    # not enough peers and mon_count > 1
    if len(units.keys()) < moncount:
        status_set('blocked', 'Insufficient peer units to bootstrap'
                              ' cluster (require {})'.format(moncount))
        return

    # mon_count > 1, peers, but no ceph-public-address
    ready = sum(1 for unit_ready in units.values() if unit_ready)
    if ready < moncount:
        status_set('waiting', 'Peer units detected, waiting for addresses')
        return

    configured_rbd_features = config('default-rbd-features')
    if has_rbd_mirrors() and configured_rbd_features:
        if add_rbd_mirror_features(
                configured_rbd_features) != configured_rbd_features:
            # The configured RBD features bitmap does not contain the features
            # required for RBD Mirroring
            status_set('blocked', 'Configuration mismatch: RBD Mirroring '
                                  'enabled but incorrect value set for '
                                  '``default-rbd-features``')
            return

    # active - bootstrapped + quorum status check
    if ceph.is_bootstrapped() and ceph.is_quorum():
        expected_osd_count = config('expected-osd-count') or 3
        if sufficient_osds(expected_osd_count):
            status_set('active', 'Unit is ready and clustered')
        else:
            status_set(
                'waiting',
                'Monitor bootstrapped but waiting for number of'
                ' OSDs to reach expected-osd-count ({})'
                .format(expected_osd_count)
            )
    else:
        # Unit should be running and clustered, but no quorum
        # TODO: should this be blocked or waiting?
        status_set('blocked', 'Unit not clustered (no quorum)')
        # If there's a pending lock for this unit,
        # can i get the lock?
        # reboot the ceph-mon process


@hooks.hook('update-status')
@harden()
def update_status():
    log('Updating status.')


@hooks.hook('pre-series-upgrade')
def pre_series_upgrade():
    log("Running prepare series upgrade hook", "INFO")
    # NOTE: The Ceph packages handle the series upgrade gracefully.
    # In order to indicate the step of the series upgrade process for
    # administrators and automated scripts, the charm sets the paused and
    # upgrading states.
    set_unit_paused()
    set_unit_upgrading()


@hooks.hook('post-series-upgrade')
def post_series_upgrade():
    log("Running complete series upgrade hook", "INFO")
    # In order to indicate the step of the series upgrade process for
    # administrators and automated scripts, the charm clears the paused and
    # upgrading states.
    clear_unit_paused()
    clear_unit_upgrading()


if __name__ == '__main__':
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log('Unknown hook {} - skipping.'.format(e))
    assess_status()
