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
import utils


def install_upstart_scripts():
    for x in glob.glob('files/upstart/*.conf'):
        shutil.copy(x, '/etc/init/')


def install():
    utils.juju_log('INFO', 'Begin install hook.')
    utils.configure_source()
    utils.install('ceph', 'gdisk')
    install_upstart_scripts()
    utils.juju_log('INFO', 'End install hook.')


def emit_cephconf():
    cephcontext = {
        'mon_hosts': ' '.join(get_mon_hosts()),
        'fsid': get_fsid()
        }

    with open('/etc/ceph/ceph.conf', 'w') as cephconf:
        cephconf.write(utils.render_template('ceph.conf', cephcontext))


def config_changed():
    utils.juju_log('INFO', 'Begin config-changed hook.')

    utils.juju_log('INFO', 'Monitor hosts are ' + repr(get_mon_hosts()))

    if get_fsid():
        utils.juju_log('INFO', 'cluster fsid detected, rescanning disks')
        emit_cephconf()
        for dev in utils.config_get('osd-devices').split(' '):
            osdize(dev)
        subprocess.call(['udevadm', 'trigger',
                         '--subsystem-match=block', '--action=add'])

    utils.juju_log('INFO', 'End config-changed hook.')


def get_mon_hosts():
    hosts = []
    hosts.append('{}:6789'.format(utils.get_host_ip()))

    for relid in utils.relation_ids('mon'):
        for unit in utils.relation_list(relid):
            hosts.append(
                '{}:6789'.format(utils.get_host_ip(
                                    utils.relation_get('private-address',
                                                       unit, relid)))
                )

    hosts.sort()
    return hosts


def get_fsid():
    for relid in utils.relation_ids('mon'):
        for unit in utils.relation_list(relid):
            fsid = utils.relation_get('fsid',
                                      unit, relid)
            if fsid != "":
                return fsid
    return None


def osdize(dev):
    # XXX hack for instances
    subprocess.call(['umount', '/mnt'])

    if ceph.is_osd_disk(dev):
        utils.juju_log('INFO',
                       'Looks like {} is already an OSD, skipping.'
                       .format(dev))
        return

    if subprocess.call(['grep', '-wqs', dev + '1', '/proc/mounts']) == 0:
        utils.juju_log('INFO',
                       'Looks like {} is in use, skipping.'.format(dev))
        return

    if os.path.exists(dev):
        subprocess.call(['ceph-disk-prepare', dev])


def mon_relation():
    utils.juju_log('INFO', 'Begin mon-relation hook.')

    if get_fsid():
        utils.juju_log('INFO', 'mon has provided fsid - scanning disks')
        emit_cephconf()
        for dev in utils.config_get('osd-devices').split(' '):
            osdize(dev)
        subprocess.call(['udevadm', 'trigger',
                         '--subsystem-match=block', '--action=add'])
    else:
        utils.juju_log('INFO',
                       'mon cluster has not yet provided fsid')

    utils.juju_log('INFO', 'End mon-relation hook.')


def upgrade_charm():
    utils.juju_log('INFO', 'Begin upgrade-charm hook.')
    if get_fsid():
        emit_cephconf()
    install_upstart_scripts()
    utils.juju_log('INFO', 'End upgrade-charm hook.')


def start():
    # In case we're being redeployed to the same machines, try
    # to make sure everything is running as soon as possible.
    subprocess.call(['udevadm', 'trigger',
                     '--subsystem-match=block', '--action=add'])


utils.do_hooks({
        'config-changed': config_changed,
        'install': install,
        'mon-relation-departed': mon_relation,
        'mon-relation-changed': mon_relation,
        'start': start,
        'upgrade-charm': upgrade_charm,
        })

sys.exit(0)
