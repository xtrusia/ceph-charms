#!/usr/bin/python

from charmhelpers.core.hookenv import action_get, log, config, action_fail

__author__ = 'chris'

import os
import sys

sys.path.append('hooks')

import ceph

"""
Given a OSD number this script will attempt to turn that back into a mount
point and then replace the OSD with a new one.
"""


def get_disk_stats():
    try:
        # https://www.kernel.org/doc/Documentation/iostats.txt
        with open('/proc/diskstats', 'r') as diskstats:
            return diskstats.readlines()
    except IOError as err:
        log('Could not open /proc/diskstats.  Error: {}'.format(err.message))
        action_fail('replace-osd failed because /proc/diskstats could not '
                    'be opened {}'.format(err.message))
        return None


def lookup_device_name(major_number, minor_number):
    """

    :param major_number: int.  The major device number
    :param minor_number: int. The minor device number
    :return: string.  The name of the device.  Example: /dev/sda.
    Returns None on error.
    """
    diskstats = get_disk_stats()
    for line in diskstats:
        parts = line.split()
        if not len(parts) > 3:
            # Skip bogus lines
            continue
        try:
            if int(parts[0]) is major_number and int(parts[1]) is \
                    minor_number:
                # Found our device.  Return its name
                return parts[2]
        except ValueError as value_err:
            log('Could not convert {} or {} into an integer. Error: {}'
                .format(parts[0], parts[1], value_err.message))
            continue
    return None


def get_device_number(osd_number):
    """
    This function will return a tuple of (major_number, minor_number)
    device number for the given osd.
    :param osd_number: int
    :rtype : (major_number,minor_number)
    """
    path = "/var/lib/ceph/osd/ceph-{}".format(osd_number)
    info = os.lstat(path)
    major_number = os.major(info.st_dev)
    minor_number = os.minor(info.st_dev)
    return major_number, minor_number


if __name__ == '__main__':
    dead_osd_number = action_get("osd-number")
    replacement_device = action_get("replacement-device")
    major, minor = get_device_number(dead_osd_number)
    device_name = lookup_device_name(major, minor)
    osd_format = config('osd-format')
    osd_journal = config('osd-journal')

    ceph.replace_osd(dead_osd_number=dead_osd_number,
                     dead_osd_device="/dev/{}".format(device_name),
                     new_osd_device=replacement_device,
                     osd_format=osd_format,
                     osd_journal=osd_journal)
