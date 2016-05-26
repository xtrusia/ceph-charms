import time

__author__ = 'chris'
from mock import patch, call, MagicMock
import sys

sys.path.append('/home/chris/repos/ceph-osd/hooks')

from ceph import CrushLocation

import test_utils
import ceph_hooks

TO_PATCH = [
    'apt_install',
    'apt_update',
    'add_source',
    'config',
    'ceph',
    'get_conf',
    'hookenv',
    'host',
    'log',
    'service_start',
    'service_stop',
    'socket',
    'status_set',
]


def config_side_effect(*args):
    if args[0] == 'source':
        return 'cloud:trusty-kilo'
    elif args[0] == 'key':
        return 'key'
    elif args[0] == 'release-version':
        return 'cloud:trusty-kilo'


previous_node_start_time = time.time() - (9 * 60)


def monitor_key_side_effect(*args):
    if args[1] == \
            'ip-192-168-1-2_done':
        return False
    elif args[1] == \
            'ip-192-168-1-2_start':
        # Return that the previous node started 9 minutes ago
        return previous_node_start_time


class UpgradeRollingTestCase(test_utils.CharmTestCase):
    def setUp(self):
        super(UpgradeRollingTestCase, self).setUp(ceph_hooks, TO_PATCH)

    @patch('ceph_hooks.roll_osd_cluster')
    def test_check_for_upgrade(self, roll_osd_cluster):
        self.host.lsb_release.return_value = {
            'DISTRIB_CODENAME': 'trusty',
        }
        previous_mock = MagicMock().return_value
        previous_mock.previous.return_value = "cloud:trusty-juno"
        self.hookenv.config.side_effect = [previous_mock,
                                           config_side_effect('source')]
        ceph_hooks.check_for_upgrade()

        roll_osd_cluster.assert_called_with('cloud:trusty-kilo')

    @patch('ceph_hooks.upgrade_osd')
    @patch('ceph_hooks.monitor_key_set')
    def test_lock_and_roll(self, monitor_key_set, upgrade_osd):
        monitor_key_set.monitor_key_set.return_value = None
        ceph_hooks.lock_and_roll(my_name='ip-192-168-1-2')
        upgrade_osd.assert_called_once_with()

    def test_upgrade_osd(self):
        self.config.side_effect = config_side_effect
        self.ceph.get_version.return_value = "0.80"
        self.ceph.systemd.return_value = False
        ceph_hooks.upgrade_osd()
        self.service_stop.assert_called_with('ceph-osd-all')
        self.service_start.assert_called_with('ceph-osd-all')
        self.status_set.assert_has_calls([
            call('maintenance', 'Upgrading osd'),
        ])

    @patch('ceph_hooks.lock_and_roll')
    @patch('ceph_hooks.get_upgrade_position')
    def test_roll_osd_cluster_first(self,
                                    get_upgrade_position,
                                    lock_and_roll):
        self.socket.gethostname.return_value = "ip-192-168-1-2"
        self.ceph.get_osd_tree.return_value = ""
        get_upgrade_position.return_value = 0
        ceph_hooks.roll_osd_cluster('0.94.1')
        lock_and_roll.assert_called_with(my_name="ip-192-168-1-2")

    @patch('ceph_hooks.lock_and_roll')
    @patch('ceph_hooks.get_upgrade_position')
    @patch('ceph_hooks.wait_on_previous_node')
    def test_roll_osd_cluster_second(self,
                                     wait_on_previous_node,
                                     get_upgrade_position,
                                     lock_and_roll):
        wait_on_previous_node.return_value = None
        self.socket.gethostname.return_value = "ip-192-168-1-3"
        self.ceph.get_osd_tree.return_value = [
            CrushLocation(
                name="ip-192-168-1-2",
                identifier='a',
                host='host-a',
                rack='rack-a',
                row='row-a',
                datacenter='dc-1',
                chassis='chassis-a',
                root='ceph'),
            CrushLocation(
                name="ip-192-168-1-3",
                identifier='a',
                host='host-b',
                rack='rack-a',
                row='row-a',
                datacenter='dc-1',
                chassis='chassis-a',
                root='ceph')
        ]
        get_upgrade_position.return_value = 1
        ceph_hooks.roll_osd_cluster('0.94.1')
        self.status_set.assert_called_with(
            'blocked',
            'Waiting on ip-192-168-1-2 to finish upgrading')
        lock_and_roll.assert_called_with(my_name="ip-192-168-1-3")

    @patch('time.time', lambda *args: previous_node_start_time + 10 * 60 + 1)
    @patch('ceph_hooks.monitor_key_get')
    @patch('ceph_hooks.monitor_key_exists')
    def test_wait_on_previous_node(self,
                                   monitor_key_exists,
                                   monitor_key_get):
        monitor_key_get.side_effect = monitor_key_side_effect
        monitor_key_exists.return_value = False

        ceph_hooks.wait_on_previous_node("ip-192-168-1-2")

        # Make sure we checked to see if the previous node started
        monitor_key_get.assert_has_calls(
            [call('osd-upgrade', 'ip-192-168-1-2_start')]
        )
        # Make sure we checked to see if the previous node was finished
        monitor_key_exists.assert_has_calls(
            [call('osd-upgrade', 'ip-192-168-1-2_done')]
        )
        # Make sure we waited at last once before proceeding
        self.log.assert_has_calls(
            [call('Previous node is: ip-192-168-1-2')],
            [call('ip-192-168-1-2 is not finished. Waiting')],
        )
