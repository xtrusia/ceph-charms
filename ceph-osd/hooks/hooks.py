#!/usr/bin/python

#
# Copyright 2012 Canonical Ltd.
#
# Authors:
#  James Page <james.page@ubuntu.com>
#

import glob
import os
import subprocess
import shutil
import sys

import ceph
from charmhelpers.core.hookenv import (
    log,
    ERROR,
    config,
    relation_ids,
    related_units,
    relation_get,
    Hooks,
    UnregisteredHookError
)
from charmhelpers.core.host import (
    apt_install,
    apt_update,
    filter_installed_packages,
    umount
)

from utils import (
    render_template,
    configure_source,
    get_host_ip,
)

hooks = Hooks()


def install_upstart_scripts():
    # Only install upstart configurations for older versions
    if ceph.get_ceph_version() < "0.55.1":
        for x in glob.glob('files/upstart/*.conf'):
            shutil.copy(x, '/etc/init/')


@hooks.hook('install')
def install():
    log('Begin install hook.')
    configure_source(config('source'))
    apt_update(fatal=True)
    apt_install(packages=ceph.PACKAGES, error=True)
    install_upstart_scripts()
    log('End install hook.')


def emit_cephconf():
    mon_hosts = get_mon_hosts()
    log('Monitor hosts are ' + repr(mon_hosts))

    cephcontext = {
        'auth_supported': get_auth(),
        'mon_hosts': ' '.join(mon_hosts),
        'fsid': get_fsid(),
        'version': ceph.get_ceph_version()
    }

    with open('/etc/ceph/ceph.conf', 'w') as cephconf:
        cephconf.write(render_template('ceph.conf', cephcontext))

JOURNAL_ZAPPED = '/var/lib/ceph/journal_zapped'


@hooks.hook('config-changed')
def config_changed():
    log('Begin config-changed hook.')

    # Pre-flight checks
    if config('osd-format') not in ceph.DISK_FORMATS:
        log('Invalid OSD disk format configuration specified', level=ERROR)
        sys.exit(1)

    e_mountpoint = config('ephemeral-unmount')
    if (e_mountpoint and filesystem_mounted(e_mountpoint)):
        umount(e_mountpoint)

    osd_journal = config('osd-journal')
    if (osd_journal and not os.path.exists(JOURNAL_ZAPPED)
            and os.path.exists(osd_journal)):
        ceph.zap_disk(osd_journal)
        with open(JOURNAL_ZAPPED, 'w') as zapped:
            zapped.write('DONE')

    if ceph.is_bootstrapped():
        log('ceph bootstrapped, rescanning disks')
        emit_cephconf()
        for dev in config('osd-devices').split(' '):
            ceph.osdize(dev, config('osd-format'),
                        config('osd-journal'), config('osd-reformat'))
        ceph.rescan_osd_devices()

    log('End config-changed hook.')


def get_mon_hosts():
    hosts = []
    for relid in relation_ids('mon'):
        for unit in related_units(relid):
            hosts.append(
                '{}:6789'.format(get_host_ip(relation_get('private-address',
                                             unit, relid)))
            )

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


def device_mounted(dev):
    return subprocess.call(['grep', '-wqs', dev + '1', '/proc/mounts']) == 0


def filesystem_mounted(fs):
    return subprocess.call(['grep', '-wqs', fs, '/proc/mounts']) == 0


@hooks.hook('mon-relation-changed',
            'mon-relation-departed')
def mon_relation():
    log('Begin mon-relation hook.')

    bootstrap_key = relation_get('osd_bootstrap_key')
    if get_fsid() and get_auth() and bootstrap_key:
        log('mon has provided conf- scanning disks')
        emit_cephconf()
        ceph.import_osd_bootstrap_key(bootstrap_key)
        for dev in config('osd-devices').split(' '):
            ceph.osdize(dev, config('osd-format'),
                        config('osd-journal'), config('osd-reformat'))
        ceph.rescan_osd_devices()
    else:
        log('mon cluster has not yet provided conf')

    log('End mon-relation hook.')


@hooks.hook('upgrade-charm')
def upgrade_charm():
    log('Begin upgrade-charm hook.')
    if get_fsid() and get_auth():
        emit_cephconf()
    install_upstart_scripts()
    apt_install(packages=filter_installed_packages(ceph.PACKAGES),
                error=True)
    log('End upgrade-charm hook.')


if __name__ == '__main__':
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log('Unknown hook {} - skipping.'.format(e))
