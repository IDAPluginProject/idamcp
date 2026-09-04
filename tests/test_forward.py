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

"""Unit tests for HeadlessManager spawned instances tracking and forwarder."""

import unittest
from unittest import mock

from fastmcp.exceptions import ToolError
from gateway.forward import _global_client_state
from gateway.forward import _global_clients
from gateway.forward import _global_database_id_to_pid
from gateway.forward import forward_to
from gateway.forward import HeadlessManager


class TestHeadlessManager(unittest.IsolatedAsyncioTestCase):
  """Tests for HeadlessManager spawned instances tracking and quota."""

  async def asyncSetUp(self):
    self.manager = HeadlessManager(max_instances=3)
    _global_client_state.clear()
    _global_database_id_to_pid.clear()

  async def asyncTearDown(self):
    _global_client_state.clear()
    _global_database_id_to_pid.clear()

  def test_register_adds_to_spawned_instances(self):
    """Test registering adds an instance to spawned_instances and pid map."""
    self.manager.register("db1", 1001)
    self.assertIn("db1", self.manager.spawned_instances)
    self.assertEqual(_global_database_id_to_pid.get("db1"), 1001)

  async def test_unregister_removes_from_spawned_instances(self):
    """Test that unregistering removes an instance from spawned_instances."""
    self.manager.register("db1", 1001)
    self.assertIn("db1", self.manager.spawned_instances)

    with mock.patch("gateway.forward._is_process_running", return_value=False):
      await self.manager.unregister("db1")

    self.assertNotIn("db1", self.manager.spawned_instances)
    self.assertNotIn("db1", _global_database_id_to_pid)

  async def test_close_calls_disconnect_backend(self):
    """Test that close delegates to disconnect_backend."""
    with mock.patch("gateway.forward.disconnect_backend") as mock_disconnect:
      await self.manager.close("db1")
      mock_disconnect.assert_called_once_with("db1")

  async def test_spawn_raises_error_when_limit_reached(self):
    """Test that spawn raises ToolError when max_instances limit is reached."""
    self.manager.register("db1", 1001)
    self.manager.register("db2", 1002)
    self.manager.register("db3", 1003)

    with (
        mock.patch("os.path.abspath", return_value="/fake/path/bin"),
        mock.patch("os.path.exists", return_value=True),
    ):
      with self.assertRaises(ToolError) as ctx:
        await self.manager.spawn("/fake/path/bin")

      self.assertIn(
          "Maximum number of headless IDA instances (3) reached",
          str(ctx.exception),
      )
      self.assertIn("idalib_headless_close", str(ctx.exception))

  async def test_spawn_succeeds_after_closing_instance(self):
    """Test that closing an instance frees capacity to spawn again."""
    self.manager.register("db1", 1001)
    self.manager.register("db2", 1002)
    self.manager.register("db3", 1003)
    self.assertEqual(len(self.manager.spawned_instances), 3)

    # Unregister db1 (simulate close)
    with mock.patch("gateway.forward._is_process_running", return_value=False):
      await self.manager.unregister("db1")

    self.assertEqual(len(self.manager.spawned_instances), 2)

  async def test_forward_to_succeeds(self):
    """Test that forward_to forwards tool calls to client successfully."""
    mock_client = mock.AsyncMock()
    mock_client.call.return_value = {"status": "ok"}
    _global_clients["test_db"] = mock_client

    result = await forward_to("test_db", "ping", {})
    self.assertEqual(result, {"status": "ok"})
