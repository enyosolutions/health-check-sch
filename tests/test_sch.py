#!/usr/bin/env python

"""Tests for `sch` package."""


import unittest
from click.testing import CliRunner

from sch import cli


class TestSch(unittest.TestCase):
    """Tests for `sch` package."""

    def setUp(self):
        """Set up test fixtures, if any."""

    def tearDown(self):
        """Tear down test fixtures, if any."""

    def test_000_something(self):
        """Test something."""

    @staticmethod
    def test_command_line_interface():
        """Test the CLI."""
        runner = CliRunner()

        help_result = runner.invoke(cli.main, ['--help'])
        assert help_result.exit_code == 0
        assert 'Show this message and exit.' in help_result.output

        list_help_result = runner.invoke(cli.main, ['list', '--help'])
        assert list_help_result.exit_code == 0
        list_help_text = 'List checks for the configured Healthchecks project.'
        assert list_help_text in list_help_result.output
