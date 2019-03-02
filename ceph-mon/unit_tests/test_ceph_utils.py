# Copyright 2019 Canonical Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import mock

import test_utils

from hooks import utils


class CephUtilsTestCase(test_utils.CharmTestCase):

    def setUp(self):
        super().setUp()

    @mock.patch.object(utils, 'related_units')
    @mock.patch.object(utils, 'relation_ids')
    def test_has_rbd_mirrors(self, _relation_ids, _related_units):
        # NOTE(fnordahl): This optimization will not be useful until we get a
        # resolution on LP: #1818245
        # _goal_state.return_value = {'relations': {'rbd-mirror': None}}
        # self.assertTrue(utils.has_rbd_mirrors())
        # _goal_state.assert_called_once_with()
        # _goal_state.side_effect = NotImplementedError
        _relation_ids.return_value = ['arelid']
        _related_units.return_value = ['aunit/0']
        self.assertTrue(utils.has_rbd_mirrors())
        _relation_ids.assert_called_once_with('rbd-mirror')
        _related_units.assert_called_once_with('arelid')

    @mock.patch.object(utils.subprocess, 'check_output')
    def test_get_default_rbd_features(self, _check_output):
        _check_output.return_value = ('a = b\nrbd_default_features = 61\n'
                                      'c = d\n')
        self.assertEquals(
            utils.get_default_rbd_features(),
            61)
        _check_output.assert_called_once_with(
            ['ceph', '-c', '/dev/null', '--show-config'],
            universal_newlines=True)

    def test_add_mirror_rbd_features(self):
        DEFAULT_FEATURES = 61
        RBD_FEATURE_EXCLUSIVE_LOCK = 4
        RBD_FEATURE_JOURNALING = 64
        COMBINED_FEATURES = (DEFAULT_FEATURES | RBD_FEATURE_EXCLUSIVE_LOCK |
                             RBD_FEATURE_JOURNALING)
        self.assertEqual(utils.add_rbd_mirror_features(DEFAULT_FEATURES),
                         COMBINED_FEATURES)

    @mock.patch.object(utils, 'get_default_rbd_features')
    @mock.patch.object(utils, 'has_rbd_mirrors')
    @mock.patch.object(utils, 'config')
    def test_get_rbd_features(self, _config, _has_rbd_mirrors,
                              _get_default_rbd_features):
        _config.side_effect = \
            lambda key: {'default-rbd-features': 42}.get(key, None)
        self.assertEquals(utils.get_rbd_features(), 42)
        _has_rbd_mirrors.return_value = True
        _get_default_rbd_features.return_value = 61
        _config.side_effect = lambda key: {}.get(key, None)
        self.assertEquals(utils.get_rbd_features(), 125)
        _has_rbd_mirrors.return_value = False
        self.assertEquals(utils.get_rbd_features(), None)
