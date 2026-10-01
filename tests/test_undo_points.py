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

"""Unit tests for GUI undo points created before write tool calls."""

import enum
import pathlib
import sys
import types
import unittest
from unittest import mock

root_dir = pathlib.Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
  sys.path.insert(0, str(root_dir))

for _module in ("idaapi", "ida_kernwin", "idc"):
  if _module not in sys.modules:
    sys.modules[_module] = mock.MagicMock()

# pylint: disable=g-import-not-at-top,g-bad-import-order
from ida_mcp.core import synchronization
import idaapi


class _Safety(enum.IntEnum):
  """Distinct values; the real enum can alias when ida_kernwin is mocked."""

  SAFE_NONE = 0
  SAFE_READ = 1
  SAFE_WRITE = 2


class TestGuiUndoPoints(unittest.TestCase):
  """Tests for _create_undo_point and its call site in _IDACall._runned."""

  def setUp(self):
    self.events = []
    self.undo = types.SimpleNamespace(
        create_undo_point=mock.Mock(
            side_effect=lambda a, l: self.events.append(("undo", a, l)) or True
        )
    )
    self.config = {"gui_undo_points": True}
    self.patches = [
        mock.patch.object(synchronization, "IDASafety", _Safety),
        mock.patch.object(synchronization, "_undo_points_disabled", False),
        mock.patch.object(idaapi, "is_headless", False, create=True),
        mock.patch.dict(sys.modules, {"ida_undo": self.undo}),
        mock.patch(
            "shared.config.load_config", side_effect=lambda: self.config
        ),
        mock.patch.object(
            synchronization, "get_cancellation_token", return_value=None
        ),
    ]
    for p in self.patches:
      p.start()

  def tearDown(self):
    for p in reversed(self.patches):
      p.stop()

  def _tool(self, result="ok", exc=None):
    def my_tool():
      self.events.append(("tool",))
      if exc is not None:
        raise exc
      return result

    return my_tool

  def _run(self, ff, mode):
    call = synchronization._IDACall(ff, mode)
    call._runned()
    return call

  def test_write_call_creates_labeled_point_before_tool(self):
    call = self._run(self._tool(), _Safety.SAFE_WRITE)
    self.assertEqual(
        self.events,
        [("undo", "idamcp:my_tool", "MCP: my_tool"), ("tool",)],
    )
    self.assertEqual(call.get_result(), "ok")

  def test_point_created_even_if_tool_raises(self):
    call = self._run(self._tool(exc=ValueError("x")), _Safety.SAFE_WRITE)
    self.assertEqual(self.events[0][0], "undo")
    with self.assertRaises(ValueError):
      call.get_result()

  def test_read_call_has_no_point(self):
    self._run(self._tool(), _Safety.SAFE_READ)
    self.assertEqual(self.events, [("tool",)])

  def test_headless_has_no_point(self):
    with mock.patch.object(idaapi, "is_headless", True, create=True):
      self._run(self._tool(), _Safety.SAFE_WRITE)
    self.assertEqual(self.events, [("tool",)])

  def test_config_off_has_no_point(self):
    self.config = {"gui_undo_points": False}
    self._run(self._tool(), _Safety.SAFE_WRITE)
    self.assertEqual(self.events, [("tool",)])

  def test_default_config_has_no_point(self):
    self.config = {}
    self._run(self._tool(), _Safety.SAFE_WRITE)
    self.assertEqual(self.events, [("tool",)])

  def test_missing_api_disables_and_logs_once(self):
    del self.undo.create_undo_point
    with self.assertLogs(synchronization.logger, level="ERROR") as logs:
      call = self._run(self._tool(), _Safety.SAFE_WRITE)
      self._run(self._tool(), _Safety.SAFE_WRITE)
    self.assertEqual(len(logs.records), 1)
    self.assertTrue(synchronization._undo_points_disabled)
    self.assertEqual(call.get_result(), "ok")
    self.assertEqual(self.events, [("tool",), ("tool",)])

  def test_unexpected_signature_disables_without_breaking_tool(self):
    self.undo.create_undo_point = mock.Mock(side_effect=TypeError("args"))
    with self.assertLogs(synchronization.logger, level="ERROR"):
      call = self._run(self._tool(result=42), _Safety.SAFE_WRITE)
    self.assertEqual(call.get_result(), 42)
    self._run(self._tool(), _Safety.SAFE_WRITE)
    self.undo.create_undo_point.assert_called_once()

  def test_undo_disabled_in_ida_returns_false_is_ignored(self):
    self.undo.create_undo_point = mock.Mock(return_value=False)
    call = self._run(self._tool(), _Safety.SAFE_WRITE)
    self._run(self._tool(), _Safety.SAFE_WRITE)
    self.assertEqual(call.get_result(), "ok")
    self.assertEqual(self.undo.create_undo_point.call_count, 2)
    self.assertFalse(synchronization._undo_points_disabled)

  def test_nested_call_on_main_thread_has_no_point(self):
    with mock.patch.object(idaapi, "is_main_thread", return_value=True):
      synchronization._IDACall(self._tool(), _Safety.SAFE_WRITE).execute_sync()
    self.assertEqual(self.events, [("tool",)])


if __name__ == "__main__":
  unittest.main()
