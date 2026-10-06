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

"""Unit tests for the optional flush after @idawrite calls (no IDA)."""

import enum
import pathlib
import sys
import types
import unittest
from unittest import mock

root_dir = pathlib.Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
  sys.path.insert(0, str(root_dir))

for module in ("ida_auto", "ida_kernwin", "idaapi", "idc", "ida_idaapi"):
  if module not in sys.modules:
    sys.modules[module] = mock.MagicMock()

# pylint: disable=g-import-not-at-top
from ida_mcp.core import synchronization

# pylint: enable=g-import-not-at-top


class IDASafety(enum.IntEnum):
  """Stand-in for synchronization.IDASafety with distinct values.

  With ida_kernwin mocked, the real enum's MFF_* values can all be equal (a
  MagicMock converts to 1), which makes SAFE_READ an alias of SAFE_WRITE.
  """

  SAFE_NONE = 0
  SAFE_READ = 1
  SAFE_WRITE = 2


def _config(enabled: bool):
  return mock.patch(
      "shared.config.load_config",
      return_value={"flush_after_write": enabled},
  )


class TestFlushAfterWrite(unittest.TestCase):
  """Tests for synchronization._flush_after_write and its call site."""

  def setUp(self):
    synchronization._flush_available = True
    self.calls = []
    self.loader = types.SimpleNamespace(
        flush_buffers=lambda: self.calls.append("flush") or 0
    )
    for patcher in (
        mock.patch.dict(sys.modules, {"ida_loader": self.loader}),
        mock.patch.object(synchronization, "IDASafety", IDASafety),
    ):
      patcher.start()
      self.addCleanup(patcher.stop)
    self.addCleanup(setattr, synchronization, "_flush_available", True)

  def test_disabled_by_default_config(self):
    with _config(False):
      synchronization._flush_after_write()
    self.assertEqual(self.calls, [])

  def test_enabled_flushes(self):
    with _config(True):
      synchronization._flush_after_write()
      synchronization._flush_after_write()
    self.assertEqual(self.calls, ["flush", "flush"])

  def test_missing_api_disables_and_logs_once(self):
    del self.loader.flush_buffers
    with _config(True), self.assertLogs(synchronization.logger, "ERROR") as cm:
      synchronization._flush_after_write()
      synchronization._flush_after_write()
    self.assertFalse(synchronization._flush_available)
    self.assertEqual(len(cm.output), 1)
    self.assertIn("not available", cm.output[0])

  def test_flush_error_disables_without_raising(self):
    def boom():
      self.calls.append("flush")
      raise RuntimeError("license tier")

    self.loader.flush_buffers = boom
    with _config(True), self.assertLogs(synchronization.logger, "ERROR") as cm:
      synchronization._flush_after_write()
      synchronization._flush_after_write()
    self.assertEqual(self.calls, ["flush"])
    self.assertEqual(len(cm.output), 1)
    self.assertIn("license tier", cm.output[0])

  def test_write_call_flushes_after_function(self):
    order = []
    self.loader.flush_buffers = lambda: order.append("flush")
    call = synchronization._IDACall(
        lambda: order.append("tool") or 42, IDASafety.SAFE_WRITE
    )
    with _config(True):
      call._runned()
    self.assertEqual(order, ["tool", "flush"])
    self.assertEqual(call.get_result(), 42)

  def test_write_call_flushes_even_if_function_raises(self):
    def failing_tool():
      raise ValueError("bad input")

    call = synchronization._IDACall(failing_tool, IDASafety.SAFE_WRITE)
    with _config(True):
      call._runned()
    self.assertEqual(self.calls, ["flush"])
    with self.assertRaisesRegex(ValueError, "bad input"):
      call.get_result()

  def test_flush_failure_does_not_change_tool_result(self):
    def boom():
      raise RuntimeError("disk full")

    self.loader.flush_buffers = boom
    call = synchronization._IDACall(lambda: "ok", IDASafety.SAFE_WRITE)
    with _config(True), self.assertLogs(synchronization.logger, "ERROR"):
      call._runned()
    self.assertEqual(call.get_result(), "ok")

  def test_read_call_does_not_flush(self):
    call = synchronization._IDACall(lambda: 1, IDASafety.SAFE_READ)
    with _config(True):
      call._runned()
    self.assertEqual(self.calls, [])


if __name__ == "__main__":
  unittest.main()
