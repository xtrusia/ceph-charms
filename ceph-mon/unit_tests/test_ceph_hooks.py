import copy
import json
import unittest
import sys

from mock import patch, MagicMock, DEFAULT, call

# python-apt is not installed as part of test-requirements but is imported by
# some charmhelpers modules so create a fake import.
mock_apt = MagicMock()
sys.modules['apt'] = mock_apt
mock_apt.apt_pkg = MagicMock()

import charmhelpers.contrib.storage.linux.ceph as ceph
import test_utils

with patch('charmhelpers.contrib.hardening.harden.harden') as mock_dec:
    mock_dec.side_effect = (lambda *dargs, **dkwargs: lambda f:
                            lambda *args, **kwargs: f(*args, **kwargs))
    import ceph_hooks


TO_PATCH = [
    'config',
    'is_leader',
    'is_relation_made',
    'leader_get',
    'leader_set',
    'log',
    'mon_relation',
    'relation_ids',
    'related_units',
    'relation_get',
    'relations_of_type',
    'status_set',
]

CHARM_CONFIG = {'config-flags': '',
                'auth-supported': False,
                'fsid': '1234',
                'loglevel': 1,
                'use-syslog': True,
                'osd-journal-size': 1024,
                'use-direct-io': True,
                'osd-format': 'ext4',
                'monitor-hosts': '',
                'prefer-ipv6': False,
                'default-rbd-features': None,
                'nagios_degraded_thresh': '1',
                'nagios_misplaced_thresh': '10',
                'nagios_recovery_rate': '1',
                'nagios_raise_nodeepscrub': True,
                'disable-pg-max-object-skew': False}


class CephHooksTestCase(unittest.TestCase):
    def setUp(self):
        super(CephHooksTestCase, self).setUp()

    @patch.object(ceph_hooks, 'get_rbd_features', return_value=None)
    @patch.object(ceph_hooks, 'get_public_addr', lambda *args: "10.0.0.1")
    @patch.object(ceph_hooks, 'get_cluster_addr', lambda *args: "10.1.0.1")
    @patch.object(ceph_hooks, 'cmp_pkgrevno', lambda *args: 1)
    @patch.object(ceph_hooks, 'get_mon_hosts', lambda *args: ['10.0.0.1',
                                                              '10.0.0.2'])
    @patch.object(ceph_hooks, 'get_networks', lambda *args: "")
    @patch.object(ceph_hooks, 'leader_get', lambda *args: '1234')
    @patch.object(ceph, 'config')
    @patch.object(ceph_hooks, 'config')
    def test_get_ceph_context(self, mock_config, mock_config2,
                              _get_rbd_features):
        config = copy.deepcopy(CHARM_CONFIG)
        mock_config.side_effect = lambda key: config[key]
        mock_config2.side_effect = lambda key: config[key]
        ctxt = ceph_hooks.get_ceph_context()
        expected = {'auth_supported': False,
                    'ceph_cluster_network': '',
                    'ceph_public_network': '',
                    'cluster_addr': '10.1.0.1',
                    'dio': 'true',
                    'fsid': '1234',
                    'loglevel': 1,
                    'mon_hosts': '10.0.0.1 10.0.0.2',
                    'old_auth': False,
                    'public_addr': '10.0.0.1',
                    'use_syslog': 'true'}
        self.assertEqual(ctxt, expected)

    @patch.object(ceph_hooks, 'get_rbd_features', return_value=1)
    @patch.object(ceph_hooks, 'get_public_addr', lambda *args: "10.0.0.1")
    @patch.object(ceph_hooks, 'get_cluster_addr', lambda *args: "10.1.0.1")
    @patch.object(ceph_hooks, 'cmp_pkgrevno',
                  lambda pkg, ver: -1 if ver == '12.1.0' else 1)
    @patch.object(ceph_hooks, 'get_mon_hosts', lambda *args: ['10.0.0.1',
                                                              '10.0.0.2'])
    @patch.object(ceph_hooks, 'get_networks', lambda *args: "")
    @patch.object(ceph_hooks, 'leader_get', lambda *args: '1234')
    @patch.object(ceph, 'config')
    @patch.object(ceph_hooks, 'config')
    def test_get_ceph_context_rbd_features(self, mock_config, mock_config2,
                                           _get_rbd_features):
        config = copy.deepcopy(CHARM_CONFIG)
        mock_config.side_effect = lambda key: config[key]
        mock_config2.side_effect = lambda key: config[key]
        ctxt = ceph_hooks.get_ceph_context()
        expected = {'auth_supported': False,
                    'ceph_cluster_network': '',
                    'ceph_public_network': '',
                    'cluster_addr': '10.1.0.1',
                    'dio': 'true',
                    'fsid': '1234',
                    'loglevel': 1,
                    'mon_hosts': '10.0.0.1 10.0.0.2',
                    'old_auth': False,
                    'public_addr': '10.0.0.1',
                    'use_syslog': 'true',
                    'rbd_features': 1}
        self.assertEqual(ctxt, expected)

    @patch.object(ceph_hooks, 'get_rbd_features', return_value=None)
    @patch.object(ceph_hooks, 'get_public_addr', lambda *args: "10.0.0.1")
    @patch.object(ceph_hooks, 'get_cluster_addr', lambda *args: "10.1.0.1")
    @patch.object(ceph_hooks, 'cmp_pkgrevno', lambda *args: 1)
    @patch.object(ceph_hooks, 'get_mon_hosts', lambda *args: ['10.0.0.1',
                                                              '10.0.0.2'])
    @patch.object(ceph_hooks, 'get_networks', lambda *args: "")
    @patch.object(ceph_hooks, 'leader_get', lambda *args: '1234')
    @patch.object(ceph, 'config')
    @patch.object(ceph_hooks, 'config')
    def test_get_ceph_context_w_config_flags(self, mock_config, mock_config2,
                                             _get_rbd_features):
        config = copy.deepcopy(CHARM_CONFIG)
        config['config-flags'] = '{"mon": {"mon sync max retries": 10}}'
        mock_config.side_effect = lambda key: config[key]
        mock_config2.side_effect = lambda key: config[key]
        ctxt = ceph_hooks.get_ceph_context()
        expected = {'auth_supported': False,
                    'ceph_cluster_network': '',
                    'ceph_public_network': '',
                    'cluster_addr': '10.1.0.1',
                    'dio': 'true',
                    'fsid': '1234',
                    'loglevel': 1,
                    'mon_hosts': '10.0.0.1 10.0.0.2',
                    'old_auth': False,
                    'mon': {'mon sync max retries': 10},
                    'public_addr': '10.0.0.1',
                    'use_syslog': 'true'}
        self.assertEqual(ctxt, expected)

    @patch.object(ceph_hooks, 'get_rbd_features', return_value=None)
    @patch.object(ceph_hooks, 'get_public_addr', lambda *args: "10.0.0.1")
    @patch.object(ceph_hooks, 'get_cluster_addr', lambda *args: "10.1.0.1")
    @patch.object(ceph_hooks, 'cmp_pkgrevno', lambda *args: 1)
    @patch.object(ceph_hooks, 'get_mon_hosts', lambda *args: ['10.0.0.1',
                                                              '10.0.0.2'])
    @patch.object(ceph_hooks, 'get_networks', lambda *args: "")
    @patch.object(ceph_hooks, 'leader_get', lambda *args: '1234')
    @patch.object(ceph, 'config')
    @patch.object(ceph_hooks, 'config')
    def test_get_ceph_context_w_config_flags_invalid(self, mock_config,
                                                     mock_config2,
                                                     _get_rbd_features):
        config = copy.deepcopy(CHARM_CONFIG)
        config['config-flags'] = ('{"mon": {"mon sync max retries": 10},'
                                  '"foo": "bar"}')
        mock_config.side_effect = lambda key: config[key]
        mock_config2.side_effect = lambda key: config[key]
        ctxt = ceph_hooks.get_ceph_context()
        expected = {'auth_supported': False,
                    'ceph_cluster_network': '',
                    'ceph_public_network': '',
                    'cluster_addr': '10.1.0.1',
                    'dio': 'true',
                    'fsid': '1234',
                    'loglevel': 1,
                    'mon_hosts': '10.0.0.1 10.0.0.2',
                    'old_auth': False,
                    'mon': {'mon sync max retries': 10},
                    'public_addr': '10.0.0.1',
                    'use_syslog': 'true'}
        self.assertEqual(ctxt, expected)

    @patch.object(ceph_hooks, 'config')
    def test_nrpe_dependency_installed(self, mock_config):
        config = copy.deepcopy(CHARM_CONFIG)
        mock_config.side_effect = lambda key: config[key]
        with patch.multiple(ceph_hooks,
                            apt_install=DEFAULT,
                            rsync=DEFAULT,
                            log=DEFAULT,
                            write_file=DEFAULT,
                            nrpe=DEFAULT) as mocks:
            ceph_hooks.update_nrpe_config()
        mocks["apt_install"].assert_called_once_with(
            ["python-dbus", "lockfile-progs"])

    @patch.object(ceph_hooks, 'notify_rbd_mirrors')
    @patch.object(ceph_hooks, 'service_pause')
    @patch.object(ceph_hooks, 'notify_radosgws')
    @patch.object(ceph_hooks, 'ceph')
    @patch.object(ceph_hooks, 'notify_client')
    @patch.object(ceph_hooks, 'config')
    def test_upgrade_charm_with_nrpe_relation_installs_dependencies(
            self,
            mock_config,
            mock_notify_client,
            mock_ceph,
            mock_notify_radosgws,
            mock_service_pause,
            mock_notify_rbd_mirrors):
        config = copy.deepcopy(CHARM_CONFIG)
        mock_config.side_effect = lambda key: config[key]
        with patch.multiple(
                ceph_hooks,
                apt_install=DEFAULT,
                rsync=DEFAULT,
                log=DEFAULT,
                write_file=DEFAULT,
                nrpe=DEFAULT,
                emit_cephconf=DEFAULT,
                mon_relation_joined=DEFAULT,
                is_relation_made=DEFAULT) as mocks, patch(
                    "charmhelpers.contrib.hardening.harden.config"):
            mocks["is_relation_made"].return_value = True
            ceph_hooks.upgrade_charm()
        mocks["apt_install"].assert_called_with(
            ["python-dbus", "lockfile-progs"])
        mock_notify_client.assert_called_once_with()
        mock_notify_radosgws.assert_called_once_with()
        mock_ceph.update_monfs.assert_called_once_with()
        mock_service_pause.assert_called_with('ceph-create-keys')

    @patch.object(ceph_hooks, 'mds_relation_joined')
    @patch.object(ceph_hooks, 'admin_relation_joined')
    @patch.object(ceph_hooks, 'client_relation')
    @patch.object(ceph_hooks, 'related_units')
    @patch.object(ceph_hooks, 'relation_ids')
    def test_notify_client(self, mock_relation_ids, mock_related_units,
                           mock_client_relation,
                           mock_admin_relation_joined,
                           mock_mds_relation_joined):
        mock_relation_ids.return_value = ['arelid']
        mock_related_units.return_value = ['aunit']
        ceph_hooks.notify_client()
        mock_relation_ids.assert_has_calls([
            call('client'),
            call('admin'),
            call('mds'),
        ])
        mock_related_units.assert_called_with('arelid')
        mock_client_relation.assert_called_once_with('arelid', 'aunit')
        mock_admin_relation_joined.assert_called_once_with('arelid')
        mock_mds_relation_joined.assert_called_once_with(relid='arelid',
                                                         unit='aunit')

    @patch.object(ceph_hooks, 'rbd_mirror_relation')
    @patch.object(ceph_hooks, 'related_units')
    @patch.object(ceph_hooks, 'relation_ids')
    def test_notify_rbd_mirrors(self, mock_relation_ids, mock_related_units,
                                mock_rbd_mirror_relation):
        mock_relation_ids.return_value = ['arelid']
        mock_related_units.return_value = ['aunit']
        ceph_hooks.notify_rbd_mirrors()
        mock_relation_ids.assert_called_once_with('rbd-mirror')
        mock_related_units.assert_called_once_with('arelid')
        mock_rbd_mirror_relation.assert_called_once_with(relid='arelid',
                                                         unit='aunit',
                                                         recurse=False)

    @patch.object(ceph_hooks, 'uuid')
    @patch.object(ceph_hooks, 'relation_set')
    @patch.object(ceph_hooks, 'related_units')
    @patch.object(ceph_hooks, 'relation_ids')
    def test_notify_mons(self, mock_relation_ids, mock_related_units,
                         mock_relation_set, mock_uuid):
        mock_relation_ids.return_value = ['arelid']
        mock_related_units.return_value = ['aunit']
        mock_uuid.uuid4.return_value = 'FAKE-UUID'
        ceph_hooks.notify_mons()
        mock_relation_ids.assert_called_once_with('mon')
        mock_related_units.assert_called_once_with('arelid')
        mock_relation_set.assert_called_once_with(relation_id='arelid',
                                                  relation_settings={
                                                      'nonce': 'FAKE-UUID'})


class RelatedUnitsTestCase(unittest.TestCase):

    _units = {
        'osd:0': ['ceph-osd-a/0',
                  'ceph-osd-a/1',
                  'ceph-osd-a/2'],
        'osd:23': ['ceph-osd-b/1',
                   'ceph-osd-b/2',
                   'ceph-osd-b/3'],
    }

    def setUp(self):
        super(RelatedUnitsTestCase, self).setUp()

    @patch.object(ceph_hooks, 'relation_ids')
    @patch.object(ceph_hooks, 'related_units')
    def test_related_osd_single_relation(self,
                                         related_units,
                                         relation_ids):
        relation_ids.return_value = ['osd:0']
        related_units.side_effect = lambda x: self._units.get(x)
        self.assertTrue(ceph_hooks.related_osds())
        self.assertFalse(ceph_hooks.related_osds(6))
        relation_ids.assert_called_with('osd')
        related_units.assert_called_with('osd:0')

    @patch.object(ceph_hooks, 'relation_ids')
    @patch.object(ceph_hooks, 'related_units')
    def test_related_osd_multi_relation(self,
                                        related_units,
                                        relation_ids):
        relation_ids.return_value = ['osd:0', 'osd:23']
        related_units.side_effect = lambda x: self._units.get(x)
        self.assertTrue(ceph_hooks.related_osds())
        self.assertTrue(ceph_hooks.related_osds(6))
        self.assertFalse(ceph_hooks.related_osds(9))
        relation_ids.assert_called_with('osd')
        related_units.assert_has_calls([
            call('osd:0'),
            call('osd:23')
        ])

    @patch.object(ceph_hooks, 'relation_set')
    @patch.object(ceph_hooks, 'handle_broker_request')
    @patch.object(ceph_hooks, 'config')
    @patch.object(ceph_hooks.ceph, 'get_named_key')
    @patch.object(ceph_hooks, 'get_public_addr')
    @patch.object(ceph_hooks.hookenv, 'remote_service_name')
    @patch.object(ceph_hooks, 'ready_for_service')
    def test_client_relation(self,
                             _ready_for_service,
                             _remote_service_name,
                             _get_public_addr,
                             _get_named_key,
                             _config,
                             _handle_broker_request,
                             _relation_set):
        _remote_service_name.return_value = 'glance'
        config = copy.deepcopy(CHARM_CONFIG)
        _config.side_effect = lambda key: config[key]
        _handle_broker_request.return_value = {}
        ceph_hooks.client_relation(relid='rel1', unit='glance/0')
        _ready_for_service.assert_called_once_with()
        _get_public_addr.assert_called_once_with()
        _get_named_key.assert_called_once_with('glance')
        _handle_broker_request.assert_called_once_with(
            'rel1', 'glance/0', add_legacy_response=True)
        _relation_set.assert_called_once_with(
            relation_id='rel1',
            relation_settings={
                'key': _get_named_key(),
                'auth': False,
                'ceph-public-address': _get_public_addr()
            })
        config.update({'default-rbd-features': 42})
        _relation_set.reset_mock()
        ceph_hooks.client_relation(relid='rel1', unit='glance/0')
        _relation_set.assert_called_once_with(
            relation_id='rel1',
            relation_settings={
                'key': _get_named_key(),
                'auth': False,
                'ceph-public-address': _get_public_addr(),
                'rbd-features': 42,
            })

    @patch.object(ceph_hooks, 'config')
    @patch.object(ceph_hooks.ceph, 'get_named_key')
    @patch.object(ceph_hooks, 'get_public_addr')
    @patch.object(ceph_hooks.hookenv, 'remote_service_name')
    @patch.object(ceph_hooks, 'relation_ids', return_value=[])
    @patch.object(ceph_hooks, 'ready_for_service')
    @patch.object(ceph_hooks.ceph, 'is_quorum')
    @patch.object(ceph_hooks, 'remote_unit')
    @patch.object(ceph_hooks, 'relation_get')
    @patch.object(ceph_hooks.ceph, 'is_leader')
    @patch.object(ceph_hooks, 'process_requests')
    @patch.object(ceph_hooks, 'relation_set')
    def test_client_relation_non_rel_hook(self, relation_set,
                                          process_requests,
                                          is_leader,
                                          relation_get,
                                          remote_unit,
                                          is_quorum,
                                          ready_for_service,
                                          relation_ids,
                                          remote_service_name,
                                          get_public_addr,
                                          get_named_key,
                                          _config):
        # Check for LP #1738154
        ready_for_service.return_value = True
        process_requests.return_value = 'AOK'
        is_leader.return_value = True
        relation_get.return_value = {'broker_req': 'req'}
        remote_unit.return_value = None
        is_quorum.return_value = True
        config = copy.deepcopy(CHARM_CONFIG)
        _config.side_effect = lambda key: config[key]
        ceph_hooks.client_relation(relid='rel1', unit='glance/0')
        relation_set.assert_called_once_with(
            relation_id='rel1',
            relation_settings={
                'key': get_named_key(),
                'auth': False,
                'ceph-public-address': get_public_addr(),
                'broker-rsp-glance-0': 'AOK',
                'broker_rsp': 'AOK'})
        relation_set.reset_mock()
        remote_unit.return_value = 'glance/0'
        ceph_hooks.client_relation()
        relation_set.assert_called_once_with(
            relation_id=None,
            relation_settings={
                'key': get_named_key(),
                'auth': False,
                'ceph-public-address': get_public_addr(),
                'broker-rsp-glance-0': 'AOK',
                'broker_rsp': 'AOK'})

    @patch.object(ceph_hooks, 'relation_ids')
    @patch.object(ceph_hooks, 'notify_mons')
    @patch.object(ceph_hooks, 'notify_rbd_mirrors')
    @patch.object(ceph_hooks, 'process_requests')
    @patch.object(ceph_hooks.ceph, 'is_leader')
    @patch.object(ceph_hooks, 'relation_get')
    @patch.object(ceph_hooks, 'remote_unit')
    def test_handle_broker_request(self, mock_remote_unit, mock_relation_get,
                                   mock_ceph_is_leader,
                                   mock_broker_process_requests,
                                   mock_notify_rbd_mirrors,
                                   mock_notify_mons,
                                   mock_relation_ids):
        mock_remote_unit.return_value = 'glance/0'
        ceph_hooks.handle_broker_request('rel1', None)
        mock_remote_unit.assert_called_once_with()
        mock_relation_get.assert_called_once_with(rid='rel1', unit='glance/0')
        mock_relation_get.reset_mock()
        mock_relation_get.return_value = {'broker_req': 'FAKE-REQUEST'}
        mock_broker_process_requests.return_value = 'AOK'
        self.assertEqual(
            ceph_hooks.handle_broker_request('rel1', 'glance/0'),
            {'broker-rsp-glance-0': 'AOK'})
        mock_notify_rbd_mirrors.assert_called_with()
        mock_notify_mons.assert_called_with()
        mock_relation_get.assert_called_once_with(rid='rel1', unit='glance/0')
        self.assertEqual(
            ceph_hooks.handle_broker_request('rel1', 'glance/0',
                                             add_legacy_response=True),
            {'broker_rsp': 'AOK', 'broker-rsp-glance-0': 'AOK'})
        mock_notify_rbd_mirrors.reset_mock()
        mock_notify_mons.reset_mock()
        ceph_hooks.handle_broker_request('rel1', None, recurse=False)
        self.assertFalse(mock_notify_rbd_mirrors.called)
        self.assertFalse(mock_notify_mons.called)


class BootstrapSourceTestCase(test_utils.CharmTestCase):

    def setUp(self):
        super(BootstrapSourceTestCase, self).setUp(ceph_hooks, TO_PATCH)
        self.config.side_effect = self.test_config.get
        self.leader_get.side_effect = self.test_leader_settings.get
        self.leader_set.side_effect = self.test_leader_settings.set
        self.relation_get.side_effect = self.test_relation.get
        self.test_config.set('no-bootstrap', True)
        self.is_leader.return_value = True
        self.relation_ids.return_value = ['bootstrap-source:0']
        self.related_units.return_value = ['ceph/0', 'ceph/1', 'ceph/2']

    def test_bootstrap_source_no_bootstrap(self):
        """Ensure the config option of no-bootstrap is set to continue"""
        self.test_config.set('no-bootstrap', False)
        ceph_hooks.bootstrap_source_relation_changed()
        self.status_set.assert_called_once_with('blocked',
                                                'Cannot join the '
                                                'bootstrap-source relation '
                                                'when no-bootstrap is False')

    def test_bootstrap_source_not_leader(self):
        """Ensure the processing is deferred to the leader"""
        self.is_leader.return_value = False
        ceph_hooks.bootstrap_source_relation_changed()
        self.assertEqual(self.leader_set.call_count, 0)

    def test_bootstrap_source_relation_data_not_ready(self):
        """Ensures no bootstrapping done if relation data not present"""
        ceph_hooks.bootstrap_source_relation_changed()
        expected_calls = []
        relid = 'bootstrap-source:0'
        for unit in ('ceph/0', 'ceph/1', 'ceph/2'):
            expected_calls.append(call('monitor-secret', unit, relid))
            expected_calls.append(call('fsid', unit, relid))
        self.relation_get.has_calls(expected_calls)
        self.assertEqual(self.leader_set.call_count, 0)
        self.assertEqual(self.mon_relation.call_count, 0)

    def test_bootstrap_source_good_path(self):
        """Tests the good path where all is setup and relations established"""
        self.test_relation.set({'monitor-secret': 'abcd',
                                'fsid': '1234'})
        ceph_hooks.bootstrap_source_relation_changed()
        self.leader_set.assert_called_with({'fsid': '1234',
                                            'monitor-secret': 'abcd'})
        self.mon_relation.assert_called_once_with()

    def test_bootstrap_source_different_fsid_secret(self):
        """Tests where the bootstrap relation has a different fsid"""
        self.test_relation.set({'monitor-secret': 'abcd',
                                'fsid': '1234'})
        self.test_leader_settings.set({'monitor-secret': 'mysecret',
                                       'fsid': '7890'})
        self.assertRaises(AssertionError,
                          ceph_hooks.bootstrap_source_relation_changed)

    @patch.object(ceph_hooks, 'notify_client')
    @patch.object(ceph_hooks.ceph, 'is_bootstrapped')
    @patch.object(ceph_hooks, 'emit_cephconf')
    @patch.object(ceph_hooks, 'leader_get')
    @patch.object(ceph_hooks, 'is_leader')
    @patch.object(ceph_hooks, 'relations_of_type')
    @patch.object(ceph_hooks, 'get_mon_hosts')
    @patch.object(ceph_hooks, 'check_for_upgrade')
    @patch.object(ceph_hooks, 'config')
    def test_config_changed(self,
                            _config,
                            _check_for_upgrade,
                            _get_mon_hosts,
                            _relations_of_type,
                            _is_leader,
                            _leader_get,
                            _emit_cephconf,
                            _is_bootstrapped,
                            _notify_client):
        config = copy.deepcopy(CHARM_CONFIG)
        _config.side_effect = \
            lambda key=None: config.get(key, None) if key else config
        _relations_of_type.return_value = False
        _is_leader.return_value = False
        _leader_get.side_effect = ['fsid', 'monsec']
        _is_bootstrapped.return_value = True
        ceph_hooks.config_changed()
        _check_for_upgrade.assert_called_once_with()
        _get_mon_hosts.assert_called_once_with()
        _leader_get.assert_has_calls([
            call('fsid'),
            call('monitor-secret'),
        ])
        _emit_cephconf.assert_called_once_with()
        _is_bootstrapped.assert_called_once_with()
        _notify_client.assert_called_once_with()

    @patch.object(ceph_hooks, 'emit_cephconf')
    @patch.object(ceph_hooks, 'create_sysctl')
    @patch.object(ceph_hooks, 'check_for_upgrade')
    @patch.object(ceph_hooks, 'get_mon_hosts')
    @patch.object(ceph_hooks, 'bootstrap_source_relation_changed')
    def test_config_changed_no_bootstrap_changed(self,
                                                 bootstrap_source_rel_changed,
                                                 get_mon_hosts,
                                                 check_for_upgrade,
                                                 create_sysctl,
                                                 emit_ceph_conf):
        """Tests that changing no-bootstrap invokes the bs relation changed"""
        self.relations_of_type.return_value = []
        self.is_relation_made.return_value = True
        self.test_config.set_changed('no-bootstrap', True)
        ceph_hooks.config_changed()
        bootstrap_source_rel_changed.assert_called_once()

    @patch.object(ceph_hooks, 'get_public_addr')
    def test_get_mon_hosts(self, get_public_addr):
        """Tests that bootstrap-source relations are used"""
        unit_addrs = {
            'mon:0': {
                'ceph-mon/0': '172.16.0.2',
                'ceph-mon/1': '172.16.0.3',
            },
            'bootstrap-source:1': {
                'ceph/0': '172.16.10.2',
                'ceph/1': '172.16.10.3',
                'cehp/2': '172.16.10.4',
            }
        }

        def rel_ids_side_effect(relname):
            for key in unit_addrs.keys():
                if key.split(':')[0] == relname:
                    return [key]
            return None

        def rel_get_side_effect(attr, unit, relid):
            return unit_addrs[relid][unit]

        def rel_units_side_effect(relid):
            if relid in unit_addrs:
                return unit_addrs[relid].keys()
            return []

        self.relation_ids.side_effect = rel_ids_side_effect
        self.related_units.side_effect = rel_units_side_effect
        get_public_addr.return_value = '172.16.0.4'
        self.relation_get.side_effect = rel_get_side_effect
        hosts = ceph_hooks.get_mon_hosts()
        self.assertEqual(hosts, [
            '172.16.0.2:6789', '172.16.0.3:6789', '172.16.0.4:6789',
            '172.16.10.2:6789', '172.16.10.3:6789', '172.16.10.4:6789',
        ])


class RGWRelationTestCase(test_utils.CharmTestCase):

    TO_PATCH = [
        'relation_get',
        'get_public_addr',
        'ready_for_service',
        'remote_unit',
        'apt_install',
        'filter_installed_packages',
        'leader_get',
        'ceph',
        'process_requests',
        'log',
        'relation_set',
        'config',
    ]

    test_key = 'OTQ1MDdiODYtMmZhZi00M2IwLTkzYTgtZWI0MGRhNzdmNzBlCg=='
    test_fsid = '96ca5e7d-a9e3-4af1-be2b-85621eb6a8e8'

    def setUp(self):
        super(RGWRelationTestCase, self).setUp(ceph_hooks, self.TO_PATCH)
        self.relation_get.side_effect = self.test_relation.get
        self.config.side_effect = self.test_config.get
        self.test_config.set('auth-supported', 'cephx')
        self.filter_installed_packages.side_effect = lambda pkgs: pkgs
        self.ready_for_service.return_value = True
        self.leader_get.return_value = self.test_fsid
        self.ceph.is_leader.return_value = True
        self.ceph.get_radosgw_key.return_value = self.test_key
        self.get_public_addr.return_value = '10.10.10.2'

    def test_legacy_radosgw_key(self):
        self.test_relation.set({
            'key_name': None
        })
        ceph_hooks.radosgw_relation('radosgw:1', 'ceph-radosgw/0')
        self.relation_set.assert_called_once_with(
            relation_id='radosgw:1',
            relation_settings={
                'fsid': self.test_fsid,
                'auth': self.test_config.get('auth-supported'),
                'ceph-public-address': '10.10.10.2',
                'radosgw_key': self.test_key,
            }
        )
        self.ceph.get_radosgw_key.assert_called_once_with()

    def test_per_unit_radosgw_key(self):
        self.test_relation.set({
            'key_name': 'testhostname'
        })
        ceph_hooks.radosgw_relation('radosgw:1', 'ceph-radosgw/0')
        self.relation_set.assert_called_once_with(
            relation_id='radosgw:1',
            relation_settings={
                'fsid': self.test_fsid,
                'auth': self.test_config.get('auth-supported'),
                'ceph-public-address': '10.10.10.2',
                'testhostname_key': self.test_key,
            }
        )
        self.ceph.get_radosgw_key.assert_called_once_with(name='testhostname')


class RBDMirrorRelationTestCase(test_utils.CharmTestCase):

    TO_PATCH = [
        'relation_get',
        'get_cluster_addr',
        'get_public_addr',
        'ready_for_service',
        'remote_unit',
        'apt_install',
        'filter_installed_packages',
        'leader_get',
        'ceph',
        'process_requests',
        'log',
        'relation_set',
        'config',
        'handle_broker_request',
    ]

    test_key = 'OTQ1MDdiODYtMmZhZi00M2IwLTkzYTgtZWI0MGRhNzdmNzBlCg=='

    def setUp(self):
        super(RBDMirrorRelationTestCase, self).setUp(ceph_hooks, self.TO_PATCH)
        self.relation_get.side_effect = self.test_relation.get
        self.config.side_effect = self.test_config.get
        self.test_config.set('auth-supported', 'cephx')
        self.filter_installed_packages.side_effect = lambda pkgs: pkgs
        self.ready_for_service.return_value = True
        self.ceph.is_leader.return_value = True
        self.ceph.get_rbd_mirror_key.return_value = self.test_key
        self.get_cluster_addr.return_value = '192.0.2.10'
        self.get_public_addr.return_value = '198.51.100.10'
        self.ceph.list_pools_detail.return_value = {'pool': {}}

    def test_rbd_mirror_relation(self):
        self.handle_broker_request.return_value = {}
        base_relation_settings = {
            'auth': self.test_config.get('auth-supported'),
            'ceph-public-address': '198.51.100.10',
            'ceph-cluster-address': '192.0.2.10',
            'pools': json.dumps({'pool': {}}),
        }
        ceph_hooks.rbd_mirror_relation('rbd-mirror:51', 'ceph-rbd-mirror/0')
        self.handle_broker_request.assert_called_with(
            'rbd-mirror:51', 'ceph-rbd-mirror/0', recurse=True)
        self.relation_set.assert_called_with(
            relation_id='rbd-mirror:51',
            relation_settings=base_relation_settings)
        self.test_relation.set(
            {'unique_id': None})
        ceph_hooks.rbd_mirror_relation('rbd-mirror:52', 'ceph-rbd-mirror/0')
        self.relation_set.assert_called_with(
            relation_id='rbd-mirror:52',
            relation_settings=base_relation_settings)
        self.test_relation.set(
            {'unique_id': json.dumps('otherSideIsReactiveEndpoint')})
        ceph_hooks.rbd_mirror_relation('rbd-mirror:53', 'ceph-rbd-mirror/0')
        self.ceph.get_rbd_mirror_key.assert_called_once_with(
            'rbd-mirror.otherSideIsReactiveEndpoint')
        key_relation_settings = base_relation_settings.copy()
        key_relation_settings.update(
            {'otherSideIsReactiveEndpoint_key': self.test_key})
        self.relation_set.assert_called_with(
            relation_id='rbd-mirror:53',
            relation_settings=key_relation_settings)
        self.test_relation.set({'unique_id': 'somehostname'})
        ceph_hooks.rbd_mirror_relation('rbd-mirror:42', 'ceph-rbd-mirror/0')
        self.ceph.get_rbd_mirror_key.assert_called_with(
            'rbd-mirror.somehostname')
        key_relation_settings = base_relation_settings.copy()
        key_relation_settings.update({
            'otherSideIsReactiveEndpoint_key': self.test_key,
            'somehostname_key': self.test_key
        })
        self.relation_set.assert_called_with(
            relation_id='rbd-mirror:42',
            relation_settings=key_relation_settings)
