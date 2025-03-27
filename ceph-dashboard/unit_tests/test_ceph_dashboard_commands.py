#!/usr/bin/env python3
# Copyright 2024 Canonical
# See LICENSE file for licensing details.
#
# Learn more at: https://juju.is/docs/sdk
import unittest

from ceph_dashboard_commands import _run_cmd

from unittest.mock import patch, MagicMock


class TestCephDashboardCommand(unittest.TestCase):
    @patch('ceph_dashboard_commands.subprocess.run')
    def test_run_cmd(self, mock_run):
        # Mock the Popen object and its methods
        process_mock = MagicMock()
        process_mock.stdout = 'output line 1\noutput line 2\n'
        process_mock.stderr = ''
        process_mock.returncode = 0
        mock_run.return_value = process_mock

        # Execute the function
        result = _run_cmd(['echo', 'test'])

        # Verify the result
        self.assertEqual(result, 'output line 1\noutput line 2\n')


if __name__ == "__main__":
    unittest.main()
