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

"""Unit tests for IDA MCP plugin lifecycle, database teardown, and cache cleanup."""

import pathlib
import sqlite3
import sys
import threading
import time
import unittest
from unittest import mock

# Mock IDA modules before importing query and plugin modules
MOCKED_MODULES = [
    "ida_auto",
    "ida_bytes",
    "ida_dbg",
    "ida_entry",
    "ida_frame",
    "ida_funcs",
    "ida_gdl",
    "ida_hexrays",
    "ida_ida",
    "ida_idaapi",
    "ida_idd",
    "ida_idp",
    "ida_kernwin",
    "ida_lines",
    "ida_loader",
    "ida_moves",
    "ida_nalt",
    "ida_name",
    "ida_netnode",
    "ida_segment",
    "ida_struct",
    "ida_typeinf",
    "ida_xref",
    "idaapi",
    "idautils",
    "idc",
]

module_mocks = {}
for module in MOCKED_MODULES:
  if module in sys.modules:
    module_mocks[module] = sys.modules[module]
  else:
    module_mocks[module] = mock.MagicMock()
sys.modules.update(module_mocks)

# Ensure IDB_Hooks, IDP_Hooks, and plugin_t are valid base types
setattr(
    sys.modules["ida_idp"],
    "IDB_Hooks",
    type(
        "IDB_Hooks",
        (),
        {"hook": lambda self: True, "unhook": lambda self: True},
    ),
)
setattr(
    sys.modules["ida_idp"],
    "IDP_Hooks",
    type(
        "IDP_Hooks",
        (),
        {"hook": lambda self: True, "unhook": lambda self: True},
    ),
)
setattr(sys.modules["idaapi"], "plugin_t", object)
setattr(sys.modules["idaapi"], "PLUGIN_KEEP", 2)
setattr(sys.modules["idaapi"], "idb_path", None)
setattr(sys.modules["idaapi"], "is_main_thread", lambda: True)
setattr(sys.modules["idaapi"], "auto_is_ok", lambda: True)
setattr(sys.modules["idaapi"], "is_idaq", lambda: True)
setattr(sys.modules["idaapi"], "get_path", lambda *args: "/tmp/dummy.i64")
setattr(sys.modules["idaapi"], "get_input_file_path", lambda: "/tmp/dummy.bin")
setattr(sys.modules["idc"], "get_idb_path", lambda: "/tmp/dummy.i64")
setattr(sys.modules["ida_netnode"].netnode, "exist", lambda *args: False)
setattr(sys.modules["ida_segment"], "get_segm_qty", lambda: 0)

# Ensure project root is in sys.path
repo_root = pathlib.Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
  sys.path.insert(0, str(repo_root))

from ida_mcp.core.backend_registry import RegistryManager
from ida_mcp.core.security import security_manager
from ida_mcp.server import mcp_server_thread, stop_server
from ida_mcp.tools import info
from ida_mcp.tools import query
from ida_mcp.utils import helper
from plugins.ida_mcp_plugin import MCP
import idaapi
from shared.config import load_config

MOCK_METADATA = {
    "filepath": "/tmp/dummy.bin",
    "module": "dummy",
    "database_path": "/tmp/dummy.i64",
    "imagebase": "0x400000",
    "imagesize": "0x1000",
    "sha256": "abcdef",
    "filesize": "0x1000",
    "filetype": "ELF",
    "bitness": 64,
    "procname": "metapc",
    "is_headless": False,
}


def _is_connection_open(conn: sqlite3.Connection) -> bool:
  try:
    conn.total_changes
    return True
  except (sqlite3.ProgrammingError, sqlite3.OperationalError):
    return False


class TestPluginLifecycle(unittest.TestCase):
  """Tests for plugin initialization, termination, database closing, and cache clearing."""

  def setUp(self):
    helper.get_segments = lambda: []
    query.close_tables()
    info.clear_caches()
    security_manager.reset()
    load_config.cache_clear()

  def tearDown(self):
    query.close_tables()
    info.clear_caches()
    security_manager.reset()
    load_config.cache_clear()

  def test_clear_caches(self):
    """Verifies that clear_caches clears all pagination iterator caches."""
    info._function_iterator_cache[(0, "", "")] = iter([1, 2, 3])
    info._global_iterator_cache[(0, "")] = iter([4, 5])
    info._import_iterator_cache[(0,)] = iter([6])
    info._string_iterator_cache[(0, "", "")] = iter([7, 8])

    self.assertGreater(len(info._function_iterator_cache), 0)
    self.assertGreater(len(info._global_iterator_cache), 0)
    self.assertGreater(len(info._import_iterator_cache), 0)
    self.assertGreater(len(info._string_iterator_cache), 0)

    info.clear_caches()

    self.assertEqual(len(info._function_iterator_cache), 0)
    self.assertEqual(len(info._global_iterator_cache), 0)
    self.assertEqual(len(info._import_iterator_cache), 0)
    self.assertEqual(len(info._string_iterator_cache), 0)

  def test_close_tables_lifecycle(self):
    """Verifies that close_tables unhooks hooks, stops the worker thread, and resets state."""
    res = query.init_tables()
    self.assertTrue(res)
    self.assertTrue(query._db_initialized)
    self.assertIsNotNone(query._worker_thread)
    self.assertTrue(query._worker_thread.is_alive())
    self.assertIsNotNone(query._db_hooks)
    self.assertIsNotNone(query._db_idp_hooks)

    rw_conn = query._get_rw_conn()
    self.assertIsNotNone(rw_conn)
    self.assertTrue(_is_connection_open(rw_conn))

    query.close_tables()

    self.assertFalse(query._db_initialized)
    self.assertIsNone(query._worker_thread)
    self.assertIsNone(query._db_hooks)
    self.assertIsNone(query._db_idp_hooks)
    self.assertEqual(len(query._created_tables), 0)
    self.assertEqual(len(query._db_local.connections), 0)
    self.assertFalse(_is_connection_open(rw_conn))

    # Idempotent second call should not raise
    query.close_tables()

    # Re-initialization should work cleanly after teardown
    res_reinit = query.init_tables()
    self.assertTrue(res_reinit)
    self.assertTrue(query._db_initialized)
    self.assertIsNotNone(query._worker_thread)
    query.close_tables()

  def test_sqlite_connection_local(self):
    """Verifies SQLiteConnectionLocal tracks connections and thread-local state across threads."""
    tl = query.SQLiteConnectionLocal()
    conn1 = sqlite3.connect(":memory:", check_same_thread=False)
    tl.rw_conn = conn1
    self.assertIn(conn1, tl.connections)
    self.assertTrue(_is_connection_open(conn1))

    conn2_ref = []
    worker_hasattr = []

    ready = threading.Event()
    proceed = threading.Event()

    def worker():
      c = sqlite3.connect(":memory:", check_same_thread=False)
      conn2_ref.append(c)
      tl.ro_conn = c
      ready.set()
      proceed.wait()
      worker_hasattr.append(hasattr(tl, "ro_conn"))

    t = threading.Thread(target=worker)
    t.start()
    ready.wait()

    self.assertEqual(len(conn2_ref), 1)
    conn2 = conn2_ref[0]
    self.assertIn(conn2, tl.connections)
    self.assertEqual(len(tl.connections), 2)

    # Close all connections across threads
    tl.close_all_connections()

    self.assertFalse(_is_connection_open(conn1))
    self.assertFalse(_is_connection_open(conn2))
    self.assertFalse(hasattr(tl, "rw_conn"))
    self.assertEqual(len(tl.connections), 0)

    proceed.set()
    t.join()

    # Worker thread should see ro_conn cleared from its thread dict
    self.assertEqual(worker_hasattr, [False])

  def test_security_manager_reset(self):
    """Verifies that security_manager.reset clears enabled tools."""
    security_manager.enable_all_unsafe_tools = True
    security_manager.enabled_unsafe_tools.add("patch_assembly")
    self.assertTrue(security_manager.enable_all_unsafe_tools)
    self.assertIn("patch_assembly", security_manager.enabled_unsafe_tools)

    security_manager.reset()
    self.assertFalse(security_manager.enable_all_unsafe_tools)
    self.assertEqual(len(security_manager.enabled_unsafe_tools), 0)

  @mock.patch("ida_mcp.tools.info.get_metadata.sync_call", return_value=MOCK_METADATA)
  def test_mcp_server_thread_start_and_stop(self, _mock_meta):
    """Verifies mcp_server_thread starts and cleanly shuts down via stop_server."""
    test_id = "test_lifecycle_id"
    config = load_config()
    registry_dir = pathlib.Path(config["registry_dir"])
    reg_file = registry_dir / f"{test_id}.json"

    # Start server in thread
    t = threading.Thread(target=mcp_server_thread, args=(test_id,), daemon=True)
    t.start()

    # Wait for registry file to appear
    for _ in range(50):
      if reg_file.exists():
        break
      time.sleep(0.1)

    self.assertTrue(reg_file.exists(), "Registry file should be created on start")

    # Stop the server
    stop_server(test_id)
    t.join(timeout=5.0)
    self.assertFalse(t.is_alive(), "Server thread should terminate cleanly")
    self.assertFalse(reg_file.exists(), "Registry file should be removed on shutdown")

  @mock.patch("ida_mcp.tools.info.get_metadata.sync_call", return_value=MOCK_METADATA)
  def test_mcp_plugin_term_cleanup(self, _mock_meta):
    """Verifies that MCP.term cleans up all state when database is closed."""
    plugin = MCP()
    plugin.init()

    # Set mock IDB state
    idaapi.idb_path = "/tmp/test.i64"
    info._function_iterator_cache[(0, "", "")] = iter([1])
    query.init_tables()

    # Start a server thread
    test_id = "test_plugin_term_id"
    config = load_config()
    reg_file = pathlib.Path(config["registry_dir"]) / f"{test_id}.json"

    plugin.hash_str = test_id
    plugin.server_thread = threading.Thread(
        target=mcp_server_thread, args=(test_id,), daemon=True
    )
    plugin._server_started = True
    plugin.server_thread.start()

    # Wait for server to start
    for _ in range(50):
      if reg_file.exists():
        break
      time.sleep(0.1)

    self.assertTrue(reg_file.exists())
    self.assertTrue(plugin._server_started)

    # Call term() as IDA would when user closes database
    plugin.term()

    self.assertFalse(plugin._server_started)
    self.assertIsNone(plugin.server_thread)
    self.assertIsNone(plugin.hash_str)
    self.assertFalse(reg_file.exists())
    self.assertFalse(query._db_initialized)
    self.assertEqual(len(info._function_iterator_cache), 0)
    self.assertFalse(hasattr(idaapi, "idb_path") and idaapi.idb_path is not None)


if __name__ == "__main__":
  unittest.main()
