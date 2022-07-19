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

import unittest
import os
import sys

from unittest.mock import patch
from subprocess import CalledProcessError

# import the module we want to test
os.sys.path.insert(1, os.path.join(sys.path[0], 'files/nagios'))
import check_ceph_status


@patch('subprocess.check_output')
class NagiosTestCase(unittest.TestCase):
    def test_get_daemons_versions_alligned(self, mock_subprocess):
        with open('unit_tests/ceph_versions_alligned.json', 'rb') as f:
            mock_subprocess.return_value = f.read()
        osds_versions = check_ceph_status.get_daemons_versions()
        self.assertEqual(osds_versions, set([(16, 2, 7)]))

    def test_get_daemons_versions_diverged(self, mock_subprocess):
        with open('unit_tests/ceph_versions_diverged.json', 'rb') as f:
            mock_subprocess.return_value = f.read()
        osds_versions = check_ceph_status.get_daemons_versions()
        self.assertEqual(osds_versions, set([(16, 2, 7), (17, 2, 0),
                                             (15, 2, 16)]))

    def test_get_daemons_versions_exeption(self, mock_subprocess):
        mock_subprocess.side_effect = CalledProcessError(1, 'ceph versions')
        self.assertRaises(check_ceph_status.UnknownError,
                          lambda: check_ceph_status.get_daemons_versions())

    # Version Alligned
    @patch('check_ceph_status.get_daemons_versions')
    def test_versions_alligned(self, mock_daemons_versions, mock_subprocess):
        mock_subprocess.return_value = 'ceph version 16.2.7 ' \
            '(dd0603118f56ab514f133c8d2e3adfc983942503)'.encode('UTF-8')
        mock_daemons_versions.return_value = set([(16, 2, 7)])
        args = check_ceph_status.parse_args([
            '--check_daemons_versions_consistency'])
        check_output = check_ceph_status.check_ceph_status(args)
        self.assertRegex(check_output, r"^OK: All versions alligned$")

    # Minor version diverged
    @patch('check_ceph_status.get_daemons_versions')
    def test_min_versions_diverged(self, mock_daemons_versions,
                                   mock_subprocess):
        mock_subprocess.return_value = 'ceph version 16.2.7 ' \
            '(dd0603118f56ab514f133c8d2e3adfc983942503)'.encode('UTF-8')
        mock_daemons_versions.return_value = set([(16, 2, 7), (16, 1, 7)])
        args = check_ceph_status.parse_args([
            '--check_daemons_versions_consistency'])
        self.assertRaises(check_ceph_status.WarnError,
                          lambda: check_ceph_status.check_ceph_status(args))

    # Major version ahead
    @patch('check_ceph_status.get_daemons_versions')
    def test_one_version_ahead(self, mock_daemons_versions, mock_subprocess):
        mock_subprocess.return_value = 'ceph version 16.2.7 ' \
            '(dd0603118f56ab514f133c8d2e3adfc983942503)'.encode('UTF-8')
        mock_daemons_versions.return_value = set([(16, 2, 7), (17, 2, 0)])
        args = check_ceph_status.parse_args([
            '--check_daemons_versions_consistency'])
        self.assertRaises(check_ceph_status.CriticalError,
                          lambda: check_ceph_status.check_ceph_status(args))

    # Two major version ahead
    @patch('check_ceph_status.get_daemons_versions')
    def test_two_version_ahead(self, mock_daemons_versions, mock_subprocess):
        mock_subprocess.return_value = 'ceph version 15.2.16 ' \
            '(d46a73d6d0a67a79558054a3a5a72cb561724974)'.encode('UTF-8')
        mock_daemons_versions.return_value = set([(15, 2, 16), (17, 2, 0)])
        args = check_ceph_status.parse_args([
            '--check_daemons_versions_consistency'])
        self.assertRaises(check_ceph_status.CriticalError,
                          lambda: check_ceph_status.check_ceph_status(args))

    # Major version behind
    @patch('check_ceph_status.get_daemons_versions')
    def test_version_behind(self, mock_daemons_versions, mock_subprocess):
        mock_subprocess.return_value = 'ceph version 16.2.7 ' \
            '(dd0603118f56ab514f133c8d2e3adfc983942503)'.encode('UTF-8')
        mock_daemons_versions.return_value = set([(15, 2, 16), (16, 2, 7)])
        args = check_ceph_status.parse_args([
            '--check_daemons_versions_consistency'])
        self.assertRaises(check_ceph_status.WarnError,
                          lambda: check_ceph_status.check_ceph_status(args))

    # Two major version behind
    @patch('check_ceph_status.get_daemons_versions')
    def test_two_version_behind(self, mock_daemons_versions, mock_subprocess):
        mock_subprocess.return_value = 'ceph version 17.2.0 ' \
            '(43e2e60a7559d3f46c9d53f1ca875fd499a1e35e)'.encode('UTF-8')
        mock_daemons_versions.return_value = set([(15, 2, 16), (17, 2, 0)])
        args = check_ceph_status.parse_args([
            '--check_daemons_versions_consistency'])
        self.assertRaises(check_ceph_status.CriticalError,
                          lambda: check_ceph_status.check_ceph_status(args))

    def test_get_ceph_version(self, mock_subprocess):
        mock_subprocess.return_value = 'ceph version 10.2.9 ' \
            '(2ee413f77150c0f375ff6f10edd6c8f9c7d060d0)'.encode('UTF-8')
        ceph_version = check_ceph_status.get_ceph_version()
        self.assertEqual(ceph_version, [10, 2, 9])

    # All OK, pre-luminoius
    @patch('check_ceph_status.get_ceph_version')
    def test_health_ok(self, mock_ceph_version, mock_subprocess):
        mock_ceph_version.return_value = [10, 2, 9]
        with open('unit_tests/ceph_ok.json') as f:
            tree = f.read()
        mock_subprocess.return_value = tree.encode('UTF-8')
        args = check_ceph_status.parse_args(['--degraded_thresh', '1'])
        check_output = check_ceph_status.check_ceph_status(args)
        self.assertRegex(check_output, r"^All OK$")

    # Warning, pre-luminous
    @patch('check_ceph_status.get_ceph_version')
    def test_health_warn(self, mock_ceph_version, mock_subprocess):
        mock_ceph_version.return_value = [10, 2, 9]
        with open('unit_tests/ceph_warn.json') as f:
            tree = f.read()
        mock_subprocess.return_value = tree.encode('UTF-8')
        args = check_ceph_status.parse_args("")
        self.assertRaises(check_ceph_status.WarnError,
                          lambda: check_ceph_status.check_ceph_status(args))

    # Error, pre-luminous, health_critical status
    @patch('check_ceph_status.get_ceph_version')
    def test_health_err(self, mock_ceph_version, mock_subprocess):
        mock_ceph_version.return_value = [10, 2, 9]
        with open('unit_tests/ceph_crit.json') as f:
            tree = f.read()
        mock_subprocess.return_value = tree.encode('UTF-8')
        args = check_ceph_status.parse_args("")
        self.assertRaises(check_ceph_status.CriticalError,
                          lambda: check_ceph_status.check_ceph_status(args))

    # Error, pre-luminous, overall HEALTH_ERR
    @patch('check_ceph_status.get_ceph_version')
    def test_health_crit(self, mock_ceph_version, mock_subprocess):
        mock_ceph_version.return_value = [10, 2, 9]
        with open('unit_tests/ceph_error.json') as f:
            tree = f.read()
        mock_subprocess.return_value = tree.encode('UTF-8')
        args = check_ceph_status.parse_args("")
        self.assertRaises(check_ceph_status.CriticalError,
                          lambda: check_ceph_status.check_ceph_status(args))

    # Error, pre-luminous, because misplaced ratio is too big
    @patch('check_ceph_status.get_ceph_version')
    def test_health_crit_misplaced(self, mock_ceph_version, mock_subprocess):
        mock_ceph_version.return_value = [10, 2, 9]
        with open('unit_tests/ceph_params.json') as f:
            tree = f.read()
        mock_subprocess.return_value = tree.encode('UTF-8')
        args = check_ceph_status.parse_args(['--misplaced_thresh', '0.1'])
        self.assertRaises(check_ceph_status.CriticalError,
                          lambda: check_ceph_status.check_ceph_status(args))

    # Error, pre-luminous, because recovery rate is too low
    @patch('check_ceph_status.get_ceph_version')
    def test_health_crit_recovery(self, mock_ceph_version, mock_subprocess):
        mock_ceph_version.return_value = [10, 2, 9]
        with open('unit_tests/ceph_params.json') as f:
            tree = f.read()
        mock_subprocess.return_value = tree.encode('UTF-8')
        args = check_ceph_status.parse_args(['--recovery_rate', '400'])
        self.assertRaises(check_ceph_status.CriticalError,
                          lambda: check_ceph_status.check_ceph_status(args))

    # Warning, pre-luminous, deepscrub
    @patch('check_ceph_status.get_ceph_version')
    def test_health_warn_deepscrub(self, mock_ceph_version, mock_subprocess):
        mock_ceph_version.return_value = [10, 2, 9]
        with open('unit_tests/ceph_nodeepscrub.json') as f:
            tree = f.read()
        mock_subprocess.return_value = tree.encode('UTF-8')
        args = check_ceph_status.parse_args("")
        self.assertRaises(check_ceph_status.WarnError,
                          lambda: check_ceph_status.check_ceph_status(args))

    # Error, pre-luminous, deepscrub
    @patch('check_ceph_status.get_ceph_version')
    def test_health_crit_deepscrub(self, mock_ceph_version, mock_subprocess):
        mock_ceph_version.return_value = [10, 2, 9]
        with open('unit_tests/ceph_nodeepscrub.json') as f:
            tree = f.read()
        mock_subprocess.return_value = tree.encode('UTF-8')
        args = check_ceph_status.parse_args(['--raise_nodeepscrub'])
        self.assertRaises(check_ceph_status.CriticalError,
                          lambda: check_ceph_status.check_ceph_status(args))

    # Error, pre-luminous, noout
    @patch('check_ceph_status.get_ceph_version')
    def test_health_crit_noout(self, mock_ceph_version, mock_subprocess):
        mock_ceph_version.return_value = [10, 2, 9]
        with open('unit_tests/ceph_noout.json') as f:
            tree = f.read()
        mock_subprocess.return_value = tree.encode('UTF-8')
        args = check_ceph_status.parse_args("")
        self.assertRaises(check_ceph_status.CriticalError,
                          lambda: check_ceph_status.check_ceph_status(args))

    # All OK, luminous
    @patch('check_ceph_status.get_ceph_version')
    def test_health_ok_luminous(self, mock_ceph_version, mock_subprocess):
        mock_ceph_version.return_value = [12, 2, 0]
        with open('unit_tests/ceph_ok_luminous.json') as f:
            tree = f.read()
        mock_subprocess.return_value = tree.encode('UTF-8')
        args = check_ceph_status.parse_args(['--degraded_thresh', '1'])
        check_output = check_ceph_status.check_ceph_status(args)
        self.assertRegex(check_output, r"^All OK$")

    # Warning, luminous
    @patch('check_ceph_status.get_ceph_version')
    def test_health_warn_luminous(self, mock_ceph_version, mock_subprocess):
        mock_ceph_version.return_value = [12, 2, 0]
        with open('unit_tests/ceph_many_warnings_luminous.json') as f:
            tree = f.read()
        mock_subprocess.return_value = tree.encode('UTF-8')
        args = check_ceph_status.parse_args("")
        self.assertRaises(check_ceph_status.WarnError,
                          lambda: check_ceph_status.check_ceph_status(args))

# Error, luminous, because of overall status

    # Error, luminous, because misplaced ratio is too big
    @patch('check_ceph_status.get_ceph_version')
    def test_health_critical_misplaced_luminous(self,
                                                mock_ceph_version,
                                                mock_subprocess):
        mock_ceph_version.return_value = [12, 2, 0]
        with open('unit_tests/ceph_many_warnings_luminous.json') as f:
            tree = f.read()
        mock_subprocess.return_value = tree.encode('UTF-8')
        args = check_ceph_status.parse_args(['--misplaced_thresh', '0.1'])
        self.assertRaises(check_ceph_status.CriticalError,
                          lambda: check_ceph_status.check_ceph_status(args))

    # Error, luminous, because degraded ratio is too big
    @patch('check_ceph_status.get_ceph_version')
    def test_health_critical_degraded_luminous(self,
                                               mock_ceph_version,
                                               mock_subprocess):
        mock_ceph_version.return_value = [12, 2, 0]
        with open('unit_tests/ceph_degraded_luminous.json') as f:
            tree = f.read()
        mock_subprocess.return_value = tree.encode('UTF-8')
        args = check_ceph_status.parse_args(['--degraded_thresh', '0.1'])
        self.assertRaises(check_ceph_status.CriticalError,
                          lambda: check_ceph_status.check_ceph_status(args))

    # Error, luminous, because recovery rate is too low
    @patch('check_ceph_status.get_ceph_version')
    def test_health_critical_recovery_luminous(self,
                                               mock_ceph_version,
                                               mock_subprocess):
        mock_ceph_version.return_value = [12, 2, 0]
        with open('unit_tests/ceph_many_warnings_luminous.json') as f:
            tree = f.read()
        mock_subprocess.return_value = tree.encode('UTF-8')
        args = check_ceph_status.parse_args(['--recovery_rate', '20'])
        self.assertRaises(check_ceph_status.CriticalError,
                          lambda: check_ceph_status.check_ceph_status(args))

    # Warning, luminous, deepscrub
    @patch('check_ceph_status.get_ceph_version')
    def test_health_warn_deepscrub_luminous(self,
                                            mock_ceph_version,
                                            mock_subprocess):
        mock_ceph_version.return_value = [12, 2, 0]
        with open('unit_tests/ceph_nodeepscrub_luminous.json') as f:
            tree = f.read()
        mock_subprocess.return_value = tree.encode('UTF-8')
        args = check_ceph_status.parse_args("")
        self.assertRaises(check_ceph_status.WarnError,
                          lambda: check_ceph_status.check_ceph_status(args))

    # Error, luminous, deepscrub
    @patch('check_ceph_status.get_ceph_version')
    def test_health_crit_deepscrub_luminous(self,
                                            mock_ceph_version,
                                            mock_subprocess):
        mock_ceph_version.return_value = [12, 2, 0]
        with open('unit_tests/ceph_nodeepscrub_luminous.json') as f:
            tree = f.read()
        mock_subprocess.return_value = tree.encode('UTF-8')
        args = check_ceph_status.parse_args(['--raise_nodeepscrub'])
        self.assertRaises(check_ceph_status.CriticalError,
                          lambda: check_ceph_status.check_ceph_status(args))

    # Error, luminous, noout
    @patch('check_ceph_status.get_ceph_version')
    def test_health_crit_noout_luminous(self,
                                        mock_ceph_version,
                                        mock_subprocess):
        mock_ceph_version.return_value = [12, 2, 0]
        with open('unit_tests/ceph_noout_luminous.json') as f:
            tree = f.read()
        mock_subprocess.return_value = tree.encode('UTF-8')
        args = check_ceph_status.parse_args("")
        self.assertRaises(check_ceph_status.CriticalError,
                          lambda: check_ceph_status.check_ceph_status(args))

    # Additional Ok, luminous, deepscrub
    @patch('check_ceph_status.get_ceph_version')
    def test_additional_ok_deepscrub_luminous(self,
                                              mock_ceph_version,
                                              mock_subprocess):
        mock_ceph_version.return_value = [12, 2, 0]
        with open('unit_tests/ceph_nodeepscrub_luminous.json') as f:
            tree = f.read()
        mock_subprocess.return_value = tree.encode('UTF-8')
        args = check_ceph_status.parse_args(['--additional_check', 'osd out'])
        check_output = check_ceph_status.check_ceph_status(args)
        self.assertRegex(check_output, r"^All OK$")

    # Additional warning, luminous, deepscrub
    @patch('check_ceph_status.get_ceph_version')
    def test_additional_warn_deepscrub_luminous(self,
                                                mock_ceph_version,
                                                mock_subprocess):
        mock_ceph_version.return_value = [12, 2, 0]
        with open('unit_tests/ceph_nodeepscrub_luminous.json') as f:
            tree = f.read()
        mock_subprocess.return_value = tree.encode('UTF-8')
        args = check_ceph_status.parse_args(['--additional_check', 'deep'])
        self.assertRaises(check_ceph_status.WarnError,
                          lambda: check_ceph_status.check_ceph_status(args))

    # Additional error, luminous, deepscrub
    @patch('check_ceph_status.get_ceph_version')
    def test_additional_error_deepscrub_luminous(self,
                                                 mock_ceph_version,
                                                 mock_subprocess):
        mock_ceph_version.return_value = [12, 2, 0]
        with open('unit_tests/ceph_nodeepscrub_luminous.json') as f:
            tree = f.read()
        mock_subprocess.return_value = tree.encode('UTF-8')
        args = check_ceph_status.parse_args(['--additional_check', 'deep',
                                             '--additional_check_critical'])
        self.assertRaises(check_ceph_status.CriticalError,
                          lambda: check_ceph_status.check_ceph_status(args))

    # Additional Ok, pre-luminous, deepscrub
    @patch('check_ceph_status.get_ceph_version')
    def test_additional_ok_deepscrub_pre_luminous(self,
                                                  mock_ceph_version,
                                                  mock_subprocess):
        mock_ceph_version.return_value = [10, 2, 9]
        with open('unit_tests/ceph_nodeepscrub.json') as f:
            tree = f.read()
        mock_subprocess.return_value = tree.encode('UTF-8')
        args = check_ceph_status.parse_args(['--additional_check', 'osd out'])
        check_output = check_ceph_status.check_ceph_status(args)
        self.assertRegex(check_output, r"^All OK$")

    # Additional warning, pre-luminous, deepscrub
    @patch('check_ceph_status.get_ceph_version')
    def test_additional_warn_deepscrub_pre_luminous(self,
                                                    mock_ceph_version,
                                                    mock_subprocess):
        mock_ceph_version.return_value = [10, 2, 9]
        with open('unit_tests/ceph_nodeepscrub.json') as f:
            tree = f.read()
        mock_subprocess.return_value = tree.encode('UTF-8')
        args = check_ceph_status.parse_args(['--additional_check', 'deep'])
        self.assertRaises(check_ceph_status.WarnError,
                          lambda: check_ceph_status.check_ceph_status(args))

    # Additional error, pre-luminous, deepscrub
    @patch('check_ceph_status.get_ceph_version')
    def test_additional_error_deepscrub_pre_luminous(self,
                                                     mock_ceph_version,
                                                     mock_subprocess):
        mock_ceph_version.return_value = [10, 2, 9]
        with open('unit_tests/ceph_nodeepscrub.json') as f:
            tree = f.read()
        mock_subprocess.return_value = tree.encode('UTF-8')
        args = check_ceph_status.parse_args(['--additional_check', 'deep',
                                             '--additional_check_critical'])
        self.assertRaises(check_ceph_status.CriticalError,
                          lambda: check_ceph_status.check_ceph_status(args))

    # Num OSD OK, pre-luminous
    @patch('check_ceph_status.get_ceph_version')
    def test_num_osds_ok_pre_luminous(self,
                                      mock_ceph_version,
                                      mock_subprocess):
        mock_ceph_version.return_value = [10, 2, 9]
        with open('unit_tests/ceph_ok.json') as f:
            tree = f.read()
        mock_subprocess.return_value = tree.encode('UTF-8')
        args = check_ceph_status.parse_args(['--check_num_osds'])
        check_output = check_ceph_status.check_ceph_status(args)
        self.assertRegex(check_output, r"^OK")

    # Num OSD error, pre-luminous
    @patch('check_ceph_status.get_ceph_version')
    def test_num_osds_error_pre_luminous(self,
                                         mock_ceph_version,
                                         mock_subprocess):
        mock_ceph_version.return_value = [10, 2, 9]
        with open('unit_tests/ceph_warn.json') as f:
            tree = f.read()
        mock_subprocess.return_value = tree.encode('UTF-8')
        args = check_ceph_status.parse_args(['--check_num_osds'])
        self.assertRaises(check_ceph_status.CriticalError,
                          lambda: check_ceph_status.check_ceph_status(args))

    # Num OSD OK, luminous
    @patch('check_ceph_status.get_ceph_version')
    def test_num_osds_ok_luminous(self,
                                  mock_ceph_version,
                                  mock_subprocess):
        mock_ceph_version.return_value = [12, 2, 0]
        with open('unit_tests/ceph_many_warnings_luminous.json') as f:
            tree = f.read()
        mock_subprocess.return_value = tree.encode('UTF-8')
        args = check_ceph_status.parse_args(['--check_num_osds'])
        check_output = check_ceph_status.check_ceph_status(args)
        self.assertRegex(check_output, r"^OK")

    # Num OSD error, luminous
    @patch('check_ceph_status.get_ceph_version')
    def test_num_osds_error_luminous(self,
                                     mock_ceph_version,
                                     mock_subprocess):
        mock_ceph_version.return_value = [12, 2, 0]
        with open('unit_tests/ceph_degraded_luminous.json') as f:
            tree = f.read()
        mock_subprocess.return_value = tree.encode('UTF-8')
        args = check_ceph_status.parse_args(['--check_num_osds'])
        self.assertRaises(check_ceph_status.CriticalError,
                          lambda: check_ceph_status.check_ceph_status(args))
