# Copyright (c) 2026 Google LLC
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""Unit tests for headless load options (no IDA)."""

import asyncio
import os
import tempfile
import unittest
from unittest import mock

from fastmcp.exceptions import ToolError
from gateway.forward import _global_client_state
from gateway.forward import _global_database_id_to_pid
from gateway.forward import HeadlessManager
from shared import load_options
from shared.load_options import LoadOptions
from shared.load_options import LoadOptionsError
from shared.load_options import parse_load_options


class TestParseLoadOptions(unittest.TestCase):
  """Tests for parse_load_options and LoadOptions."""

  def test_empty(self):
    for opts in (
        parse_load_options(),
        parse_load_options(" ", "", "  "),
        parse_load_options(None, None, None),
    ):
      self.assertTrue(opts.is_empty())
      self.assertEqual(opts.to_ida_args(), "")
      self.assertEqual(opts.to_cli(), [])

  def test_all_options(self):
    opts = parse_load_options("arm:ARMv7-M", "Binary file", "0x10000")
    self.assertEqual(opts, LoadOptions("arm:ARMv7-M", "Binary file", 0x10000))
    self.assertEqual(opts.to_ida_args(), '-parm:ARMv7-M -T"Binary file" -b1000')
    self.assertEqual(
        opts.to_cli(),
        [
            "--processor",
            "arm:ARMv7-M",
            "--loader",
            "Binary file",
            "--base-address",
            "0x10000",
        ],
    )

  def test_loader_without_space_is_quoted(self):
    self.assertEqual(parse_load_options(loader="ELF").to_ida_args(), '-T"ELF"')

  def test_base_address_forms(self):
    self.assertEqual(
        parse_load_options(base_address="65536").base_address, 0x10000
    )
    self.assertEqual(
        parse_load_options(base_address=0x400000).base_address, 0x400000
    )
    self.assertEqual(parse_load_options(base_address="0").to_ida_args(), "-b0")
    self.assertEqual(
        parse_load_options(base_address="0xFFFFFFFFFFFFFFF0").to_ida_args(),
        "-bFFFFFFFFFFFFFFF",
    )

  def test_rejects_unaligned_base(self):
    with self.assertRaisesRegex(LoadOptionsError, "16-byte aligned"):
      parse_load_options(base_address="0x10008")

  def test_rejects_bad_base(self):
    for bad in ("zzz", "0x", "1.5", "-0x10", str(1 << 64), True):
      with self.subTest(bad=bad), self.assertRaises(LoadOptionsError):
        parse_load_options(base_address=bad)

  def test_rejects_switch_injection(self):
    """No value can smuggle in another switch (e.g. -S runs a script)."""
    for kwargs in (
        {"processor": "metapc -Sevil.py"},
        {"processor": "-Sevil.py"},
        {"loader": "-Sevil.py"},
        {"loader": 'Binary file" -Sevil.py "'},
        {"loader": "Binary file -Sevil.py"},
        {"loader": "Binary\nfile"},
        {"processor": "arm;id"},
        {"processor": "a" * 33},
        {"loader": "b" * 65},
    ):
      with self.subTest(kwargs=kwargs), self.assertRaises(LoadOptionsError):
        parse_load_options(**kwargs)

  def test_check_applicable(self):
    opts = parse_load_options(processor="arm")
    for path in ("/x/a.i64", "/x/a.IDB"):
      with self.subTest(path=path), self.assertRaisesRegex(
          LoadOptionsError, "existing IDA database"
      ):
        load_options.check_applicable(path, opts)
    load_options.check_applicable("/x/firmware.bin", opts)
    load_options.check_applicable("/x/a.i64", LoadOptions())


class TestSpawnPassesOptions(unittest.IsolatedAsyncioTestCase):
  """HeadlessManager.spawn forwards validated options to the subprocess."""

  async def asyncSetUp(self):
    _global_client_state.clear()
    _global_database_id_to_pid.clear()
    self.tmp = tempfile.TemporaryDirectory()
    self.addCleanup(self.tmp.cleanup)
    self.bin = os.path.join(self.tmp.name, "fw.bin")
    with open(self.bin, "wb") as f:
      f.write(b"\x00" * 16)

  async def _spawn_capture_argv(self, path, options):
    process = mock.MagicMock()
    process.stdout.readline = mock.AsyncMock(return_value=b"")
    process.stderr.read = mock.AsyncMock(return_value=b"boom")
    with mock.patch(
        "asyncio.create_subprocess_exec",
        new=mock.AsyncMock(return_value=process),
    ) as exec_mock:
      with self.assertRaisesRegex(ToolError, "metadata is None"):
        await HeadlessManager(max_instances=1).spawn(path, options)
    return list(exec_mock.call_args.args)

  async def test_options_on_argv(self):
    argv = await self._spawn_capture_argv(
        self.bin, parse_load_options("arm", "Binary file", "0x8000")
    )
    self.assertEqual(argv[1:4], ["-m", "ida_mcp.headless", self.bin])
    self.assertEqual(
        argv[4:],
        [
            "--processor",
            "arm",
            "--loader",
            "Binary file",
            "--base-address",
            "0x8000",
        ],
    )

  async def test_no_options_argv_unchanged(self):
    argv = await self._spawn_capture_argv(self.bin, None)
    self.assertEqual(argv[1:], ["-m", "ida_mcp.headless", self.bin])

  async def test_options_rejected_for_database(self):
    idb = os.path.join(self.tmp.name, "a.i64")
    open(idb, "wb").close()
    with mock.patch("asyncio.create_subprocess_exec") as exec_mock:
      with self.assertRaisesRegex(ToolError, "existing IDA database"):
        await HeadlessManager(max_instances=1).spawn(
            idb, parse_load_options(processor="arm")
        )
    exec_mock.assert_not_called()


if __name__ == "__main__":
  unittest.main()
