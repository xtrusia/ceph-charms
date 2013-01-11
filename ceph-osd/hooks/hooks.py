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
    # Only install upstart configurations for older versions
    if ceph.get_ceph_version() < "0.55.1":
        for x in glob.glob('files/upstart/*.conf'):
            shutil.copy(x, '/etc/init/')


def install():
    utils.juju_log('INFO', 'Begin install hook.')
    utils.configure_source()
    utils.install('ceph', 'gdisk', 'ntp', 'btrfs-tools')
    install_upstart_scripts()
    utils.juju_log('INFO', 'End install hook.')


def emit_cephconf():
    mon_hosts = get_mon_hosts()
    utils.juju_log('INFO', 'Monitor hosts are ' + repr(mon_hosts))

    cephcontext = {
        'auth_supported': get_auth(),
        'mon_hosts': ' '.join(mon_hosts),
        'fsid': get_fsid(),
        'version': ceph.get_ceph_version()
        }

    with open('/etc/ceph/ceph.conf', 'w') as cephconf:
        cephconf.write(utils.render_template('ceph.conf', cephcontext))

JOURNAL_ZAPPED = '/var/lib/ceph/journal_zapped'


def config_changed():
    utils.juju_log('INFO', 'Begin config-changed hook.')

    # Pre-flight checks
    if utils.config_get('osd-format') not in ceph.DISK_FORMATS:
        utils.juju_log('CRITICAL',
                       'Invalid OSD disk format configuration specified')
        sys.exit(1)

    e_mountpoint = utils.config_get('ephemeral-unmount')
    if (e_mountpoint and
        filesystem_mounted(e_mountpoint)):
        subprocess.call(['umount', e_mountpoint])

    osd_journal = utils.config_get('osd-journal')
    if (osd_journal and
        not os.path.exists(JOURNAL_ZAPPED) and
        os.path.exists(osd_journal)):
        ceph.zap_disk(osd_journal)
        with open(JOURNAL_ZAPPED, 'w') as zapped:
            zapped.write('DONE')

    if ceph.is_bootstrapped():
        utils.juju_log('INFO', 'ceph bootstrapped, rescanning disks')
        emit_cephconf()
        for dev in utils.config_get('osd-devices').split(' '):
            osdize(dev)
        ceph.rescan_osd_devices()

    utils.juju_log('INFO', 'End config-changed hook.')


def get_mon_hosts():
    hosts = []
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
    return get_conf('fsid')


def get_auth():
    return get_conf('auth')


def get_conf(name):
    for relid in utils.relation_ids('mon'):
        for unit in utils.relation_list(relid):
            conf = utils.relation_get(name,
                                      unit, relid)
            if conf:
                return conf
    return None


def reformat_osd():
    if utils.config_get('osd-reformat'):
        return True
    else:
        return False


def osdize(dev):
    if not os.path.exists(dev):
        utils.juju_log('INFO',
                       'Path {} does not exist - bailing'.format(dev))
        return

    if (ceph.is_osd_disk(dev) and not
        reformat_osd()):
        utils.juju_log('INFO',
                       'Looks like {} is already an OSD, skipping.'
                       .format(dev))
        return

    if device_mounted(dev):
        utils.juju_log('INFO',
                       'Looks like {} is in use, skipping.'.format(dev))
        return

    cmd = ['ceph-disk-prepare']
    # Later versions of ceph support more options
    if ceph.get_ceph_version() >= "0.55":
        osd_format = utils.config_get('osd-format')
        if osd_format:
            cmd.append('--fs-type')
            cmd.append(osd_format)
        cmd.append(dev)
        osd_journal = utils.config_get('osd-journal')
        if (osd_journal and
            os.path.exists(osd_journal)):
            cmd.append(osd_journal)
    else:
        # Just provide the device - no other options
        # for older versions of ceph
        cmd.append(dev)
    subprocess.call(cmd)


def device_mounted(dev):
    return subprocess.call(['grep', '-wqs', dev + '1', '/proc/mounts']) == 0


def filesystem_mounted(fs):
    return subprocess.call(['grep', '-wqs', fs, '/proc/mounts']) == 0


def mon_relation():
    utils.juju_log('INFO', 'Begin mon-relation hook.')

    bootstrap_key = utils.relation_get('osd_bootstrap_key')
    if (get_fsid() and
        get_auth() and
        bootstrap_key):
        utils.juju_log('INFO', 'mon has provided conf- scanning disks')
        emit_cephconf()
        ceph.import_osd_bootstrap_key(bootstrap_key)
        for dev in utils.config_get('osd-devices').split(' '):
            osdize(dev)
        ceph.rescan_osd_devices()
    else:
        utils.juju_log('INFO',
                       'mon cluster has not yet provided conf')

    utils.juju_log('INFO', 'End mon-relation hook.')


def upgrade_charm():
    utils.juju_log('INFO', 'Begin upgrade-charm hook.')
    if (get_fsid() and
        get_auth()):
        emit_cephconf()
    install_upstart_scripts()
    utils.juju_log('INFO', 'End upgrade-charm hook.')


utils.do_hooks({
        'config-changed': config_changed,
        'install': install,
        'mon-relation-departed': mon_relation,
        'mon-relation-changed': mon_relation,
        'upgrade-charm': upgrade_charm,
        })

sys.exit(0)
