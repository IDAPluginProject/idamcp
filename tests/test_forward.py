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

import asyncio
import json
import pathlib
import tempfile
import unittest
from unittest import mock

from fastmcp.exceptions import ToolError
from gateway.forward import _backend_events
from gateway.forward import _background_tasks
from gateway.forward import _global_client_state
from gateway.forward import _global_clients
from gateway.forward import _global_database_id_to_pid
from gateway.forward import _global_metadata
from gateway.forward import _headless_manager
from gateway.forward import connect_to_backend
from gateway.forward import forward_to
from gateway.forward import HeadlessManager
from gateway.forward import idalib_headless_close
from shared.rpc import RPCServer


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

  async def test_close_discards_spawned_instances_early(self):
    """Test that close immediately discards from spawned_instances."""
    self.manager.register("db1", 1001)
    self.assertIn("db1", self.manager.spawned_instances)

    disconnect_started = asyncio.Event()

    async def slow_disconnect(db_id):
      del db_id
      # Verify that db1 has already been discarded from spawned_instances
      self.assertNotIn("db1", self.manager.spawned_instances)
      disconnect_started.set()

    with mock.patch(
        "gateway.forward.disconnect_backend", side_effect=slow_disconnect
    ):
      await self.manager.close("db1")

    self.assertTrue(disconnect_started.is_set())
    self.assertNotIn("db1", self.manager.spawned_instances)

  async def test_pending_spawns_prevents_overspawning(self):
    """Test that _pending_spawns prevents exceeding max_instances."""
    self.manager.register("db1", 1001)
    self.manager.register("db2", 1002)
    self.assertEqual(len(self.manager.spawned_instances), 2)

    # 1 slot remaining (max=3), but 1 pending spawn in-flight
    self.manager._pending_spawns = 1

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

  async def test_idalib_headless_close_discards_early_and_skips_closed(self):
    """Test idalib_headless_close discards early and guards against re-entrance."""
    _global_database_id_to_pid["db1"] = 1001
    _headless_manager.max_instances = 1
    _headless_manager.spawned_instances.add("db1")

    with mock.patch(
        "gateway.forward.disconnect_backend", new_callable=mock.AsyncMock
    ) as mock_disconnect:
      await idalib_headless_close("db1")
      self.assertNotIn("db1", _headless_manager.spawned_instances)
      mock_disconnect.assert_called_once_with("db1")

      # Mark is_closed to simulate completed close
      _global_client_state["db1"].is_closed = True
      mock_disconnect.reset_mock()

      # Calling it again should be a no-op
      await idalib_headless_close("db1")
      mock_disconnect.assert_not_called()

  async def test_unregister_spawns_background_kill_task(self):
    """Test that unregister spawns _kill_process_gracefully in background."""
    self.manager.register("db1", 1001)

    with (
        mock.patch("gateway.forward._is_process_running", return_value=True),
        mock.patch("gateway.forward._create_background_task") as mock_bg_task,
    ):
      mock_bg_task.side_effect = lambda coro: coro.close()
      await self.manager.unregister("db1")

      self.assertNotIn("db1", self.manager.spawned_instances)
      self.assertNotIn("db1", _global_database_id_to_pid)
      mock_bg_task.assert_called_once()

  async def test_disconnect_backend_skips_unregister_when_reopened(self):
    """Test that disconnect_backend skips unregister if reopened during wait."""
    from gateway.forward import disconnect_backend

    _global_database_id_to_pid["db1"] = 1001
    _headless_manager.max_instances = 1
    _headless_manager.spawned_instances.add("db1")
    _global_client_state["db1"].number_of_ongoing_calls = 1

    async def simulate_reopen():
      await asyncio.sleep(0.01)
      _headless_manager.register("db1", 1001)
      async with _global_client_state["db1"].condition:
        _global_client_state["db1"].is_closed = False
        _global_client_state["db1"].number_of_ongoing_calls = 0
        _global_client_state["db1"].condition.notify_all()

    with mock.patch(
        "gateway.forward._headless_manager.unregister"
    ) as mock_unregister:
      reopen_task = asyncio.create_task(simulate_reopen())
      await disconnect_backend("db1", unregister=True)
      await reopen_task

      mock_unregister.assert_not_called()
      self.assertIn("db1", _headless_manager.spawned_instances)

  def test_build_mcp_transforms_hybrid(self):
    """Test _build_mcp_transforms returns BM25SearchTransform for hybrid."""
    from gateway.forward import _build_mcp_transforms
    from gateway.forward import _serialize_search_results
    from fastmcp.server.transforms.search import BM25SearchTransform
    from shared.config import _DEFAULT_ALWAYS_VISIBLE_TOOLS

    with mock.patch("gateway.forward.CONFIG", {"tool_mode": "hybrid"}):
      transforms = _build_mcp_transforms()
      self.assertEqual(len(transforms), 1)
      self.assertIsInstance(transforms[0], BM25SearchTransform)
      self.assertEqual(
          set(transforms[0]._always_visible),
          set(_DEFAULT_ALWAYS_VISIBLE_TOOLS),
      )
      self.assertIs(
          transforms[0]._search_result_serializer, _serialize_search_results
      )

  def test_serialize_search_results(self):
    """Test search results end with the note, also when no tool matched."""
    from gateway.forward import _SEARCH_RESULTS_NOTE
    from gateway.forward import _serialize_search_results
    from fastmcp.tools import Tool

    def rename_addresses(names: list[str]) -> None:
      """Renames addresses."""
      del names

    tool = Tool.from_function(rename_addresses)
    for tools, first_line in (
        ([tool], "### rename_addresses"),
        ([], "No tools matched the query."),
    ):
      with self.subTest(first_line=first_line):
        result = _serialize_search_results(tools)
        self.assertTrue(result.startswith(f"{first_line}\n"))
        self.assertTrue(result.endswith(f"\n\n{_SEARCH_RESULTS_NOTE}"))

  def test_build_mcp_transforms_hybrid_custom_always_visible(self):
    """Test _build_mcp_transforms respects custom always_visible_tools."""
    from gateway.forward import _build_mcp_transforms
    from fastmcp.server.transforms.search import BM25SearchTransform

    custom_tools = ["list_available_databases", "sql_query", "patch_assembly"]
    with mock.patch(
        "gateway.forward.CONFIG",
        {"tool_mode": "hybrid", "always_visible_tools": custom_tools},
    ):
      transforms = _build_mcp_transforms()
      self.assertEqual(len(transforms), 1)
      self.assertIsInstance(transforms[0], BM25SearchTransform)
      self.assertEqual(set(transforms[0]._always_visible), set(custom_tools))

  def test_build_mcp_transforms_code_mode(self):
    """Test _build_mcp_transforms returns CodeMode for code_mode."""
    from gateway.forward import _build_mcp_transforms
    from fastmcp.experimental.transforms.code_mode import CodeMode

    with mock.patch("gateway.forward.CONFIG", {"tool_mode": "code_mode"}):
      transforms = _build_mcp_transforms()
      self.assertEqual(len(transforms), 1)
      self.assertIsInstance(transforms[0], CodeMode)

  def test_build_mcp_transforms_full(self):
    """Test _build_mcp_transforms returns empty list for full mode."""
    from gateway.forward import _build_mcp_transforms

    with mock.patch("gateway.forward.CONFIG", {"tool_mode": "full"}):
      transforms = _build_mcp_transforms()
      self.assertEqual(transforms, [])

  def test_build_mcp_instructions_hybrid(self):
    """Test hybrid-mode instructions point to search_tools."""
    from gateway.forward import _build_mcp_instructions

    with mock.patch("gateway.forward.CONFIG", {"tool_mode": "hybrid"}):
      instructions = _build_mcp_instructions() or ""
    self.assertIn("`search_tools`", instructions)
    self.assertIn("`sql_query`", instructions)

  def test_build_mcp_instructions_full(self):
    """Test full-mode instructions don't mention search_tools."""
    from gateway.forward import _build_mcp_instructions

    with mock.patch("gateway.forward.CONFIG", {"tool_mode": "full"}):
      instructions = _build_mcp_instructions() or ""
    self.assertNotIn("search_tools", instructions)
    self.assertIn("`sql_query`", instructions)

  def test_build_mcp_instructions_code_mode(self):
    """Test code_mode gets no instructions."""
    from gateway.forward import _build_mcp_instructions

    with mock.patch("gateway.forward.CONFIG", {"tool_mode": "code_mode"}):
      self.assertIsNone(_build_mcp_instructions())

  def test_shutdown_clients_ignores_sigterm(self):
    """Test shutdown_clients sets SIGTERM handler to SIG_IGN."""
    import signal
    from gateway.forward import shutdown_clients

    _global_clients.clear()
    with mock.patch("signal.signal") as mock_signal:
      shutdown_clients()
      if hasattr(signal, "SIGTERM"):
        mock_signal.assert_called_once_with(signal.SIGTERM, signal.SIG_IGN)


_DB = "c0ffee00"
# Not real processes: the tests mock _is_process_running and
# _kill_process_gracefully, so nothing is signalled.
_OLD_PID = 4_999_991
_NEW_PID = 4_999_993


class TestSpawnWithBackends(unittest.IsolatedAsyncioTestCase):
  """Tests HeadlessManager.spawn() against in-process RPC backends."""

  async def asyncSetUp(self):
    tmp = tempfile.TemporaryDirectory()
    self.addCleanup(tmp.cleanup)
    self.tmp = pathlib.Path(tmp.name)
    self.target = self.tmp / "target.bin"
    self.target.write_bytes(b"\0" * 16)
    self.record = self.tmp / f"{_DB}.json"
    self.manager = HeadlessManager(max_instances=4)
    self.alive: set[int] = set()
    self.servers: list[RPCServer] = []
    self.kill = mock.AsyncMock(name="_kill_process_gracefully")
    for patcher in (
        mock.patch("gateway.forward.REGISTRY_DIR", self.tmp),
        mock.patch("gateway.forward._headless_manager", self.manager),
        mock.patch(
            "gateway.forward._is_process_running", self.alive.__contains__
        ),
        mock.patch("gateway.forward._kill_process_gracefully", self.kill),
    ):
      patcher.start()
      self.addCleanup(patcher.stop)
    self._clear_gateway_state()

  async def asyncTearDown(self):
    for client in list(_global_clients.values()):
      await client.close()
    for server in self.servers:
      await server.close()
    await asyncio.gather(*_background_tasks, return_exceptions=True)
    self._clear_gateway_state()

  def _clear_gateway_state(self):
    _global_clients.clear()
    _global_metadata.clear()
    _global_database_id_to_pid.clear()
    _global_client_state.clear()
    _backend_events.clear()

  async def _start_backend(self, name: str, pid: int) -> RPCServer:
    """Starts a backend whose whoami returns name, and writes its record."""
    server = RPCServer({"whoami": lambda: name})
    tcp_server = await server.start_tcp("127.0.0.1", 0)
    self.servers.append(server)
    self.alive.add(pid)
    record = {
        "pid": pid,
        "channel": "tcp",
        "address": tcp_server.sockets[0].getsockname()[1],
        "name": _DB,
        "metadata": {"filepath": str(self.target)},
    }
    self.record.write_text(json.dumps(record), encoding="utf-8")
    return server

  async def _start_new_instance(self) -> None:
    """Starts the new backend, then connects as the watchdog would."""
    await self._start_backend("new", _NEW_PID)
    await connect_to_backend(self.record)

  def _patch_exec(self, before_metadata=None):
    """Patches the process start; the process prints [MCP_JSON] for _DB.

    Args:
      before_metadata: An optional coroutine function, awaited before spawn()
        gets the [MCP_JSON] line.
    """
    line = f"[MCP_JSON] {json.dumps({'database_id': _DB})}\n".encode()

    async def readline():
      if before_metadata is not None:
        await before_metadata()
      return line

    process = mock.Mock(
        pid=_NEW_PID, stdout=mock.Mock(readline=readline), stderr=None
    )
    return mock.patch(
        "asyncio.create_subprocess_exec", mock.AsyncMock(return_value=process)
    )

  async def _assert_new_instance_kept(self):
    self.kill.assert_not_called()
    self.assertEqual(_global_database_id_to_pid, {_DB: _NEW_PID})
    self.assertEqual(self.manager.spawned_instances, {_DB})
    self.assertEqual(await forward_to(_DB, "whoami", {}), "new")

  async def _crash_old_instance(self):
    """Connects an old instance of _DB, then crashes it; returns its client.

    The connection ends, but the record and the gateway state stay.
    """
    old_server = await self._start_backend("old", _OLD_PID)
    self.manager.register(_DB, _OLD_PID)
    await connect_to_backend(self.record)
    old_client = _global_clients[_DB]
    self.servers.remove(old_server)
    await old_server.close()
    self.alive.discard(_OLD_PID)
    async with asyncio.timeout(5):
      while not old_client.is_closed:
        await asyncio.sleep(0.01)
    return old_client

  async def _reopen(self, path: str) -> None:
    """Runs spawn(path); the new instance registers after [MCP_JSON]."""
    # As in a real start, the new instance writes its record after it has
    # printed [MCP_JSON], i.e. after spawn() has registered its PID.
    register = self.manager.register
    tasks = []

    def register_then_start(database_id, pid):
      register(database_id, pid)
      tasks.append(asyncio.create_task(self._start_new_instance()))

    with (
        self._patch_exec(),
        mock.patch.object(
            self.manager, "register", side_effect=register_then_start
        ),
    ):
      async with asyncio.timeout(5):
        await self.manager.spawn(path)
        await asyncio.gather(*tasks)

  async def test_reopen_after_crash_keeps_new_instance(self):
    """Test reopening a crashed instance without closing it first."""
    old_client = await self._crash_old_instance()
    with mock.patch.object(
        old_client, "call", wraps=old_client.call
    ) as old_client_call:
      await self._reopen(str(self.target))

    await self._assert_new_instance_kept()
    # No close_database request goes over the dead connection either.
    old_client_call.assert_not_called()

  async def test_reopen_after_crash_frees_quota(self):
    """Test that a crashed instance doesn't count against max_instances."""
    self.manager.max_instances = 1
    await self._crash_old_instance()
    await self._reopen(str(self.target))
    await self._assert_new_instance_kept()

  async def test_reopen_after_crash_by_another_path(self):
    """Test reopening a crashed instance by a path the records don't name."""
    link = self.tmp / "link.bin"
    try:
      link.symlink_to(self.target)
    except OSError as e:
      self.skipTest(f"cannot create a symlink: {e}")
    await self._crash_old_instance()
    await self._reopen(str(link))
    await self._assert_new_instance_kept()

  async def test_spawn_connected_before_reading_metadata(self):
    """Test spawn() when it connects before it reads [MCP_JSON]."""
    # The gateway's loop was busy while the instance printed [MCP_JSON] and
    # wrote its record, so connect_to_backend ran first.
    with self._patch_exec(before_metadata=self._start_new_instance):
      async with asyncio.timeout(5):
        await self.manager.spawn(str(self.target))

    await self._assert_new_instance_kept()
