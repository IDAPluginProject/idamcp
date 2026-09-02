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

"""Unit tests for query database update hooks and worker synchronization."""

import importlib
import queue
import sys
import threading
import unittest
from unittest import mock

# Mock IDA modules before importing query module
MOCKED_MODULES = [
    "ida_auto",
    "ida_bytes",
    "ida_entry",
    "ida_frame",
    "ida_funcs",
    "ida_gdl",
    "ida_hexrays",
    "ida_ida",
    "ida_idp",
    "ida_kernwin",
    "ida_loader",
    "ida_moves",
    "ida_nalt",
    "ida_name",
    "ida_segment",
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

# Ensure IDB_Hooks and IDP_Hooks are valid base types
sys.modules["ida_idp"].IDB_Hooks = type(
    "IDB_Hooks", (), {"hook": lambda self: True, "unhook": lambda self: True}
)
sys.modules["ida_idp"].IDP_Hooks = type(
    "IDP_Hooks", (), {"hook": lambda self: True, "unhook": lambda self: True}
)
# Prevent fallback file paths from MagicMock string conversions
sys.modules["idaapi"].idb_path = None
sys.modules["ida_loader"].get_path.return_value = None

# pylint: disable=g-import-not-at-top
from ida_mcp.tools import query

if not isinstance(getattr(query, "DBUpdateHooks", None), type):
  importlib.reload(query)
# pylint: enable=g-import-not-at-top


def _drain_queue():
  """Drains query._db_update_queue and marks all items task_done."""
  while True:
    try:
      query._db_update_queue.get_nowait()
      query._db_update_queue.task_done()
    except queue.Empty:
      break


class TestDBUpdateHooks(unittest.TestCase):
  """Tests verifying that DBUpdateHooks pushes correct events to _db_update_queue."""

  def setUp(self):
    super().setUp()
    _drain_queue()
    self.hooks = query.DBUpdateHooks()

  def tearDown(self):
    _drain_queue()
    super().tearDown()

  def test_set_func_start_enqueues_when_changed(self):
    pfn = mock.MagicMock()
    pfn.start_ea = 0x1000
    pfn.end_ea = 0x1050

    self.hooks.set_func_start(pfn, 0x1010)
    self.assertFalse(query._db_update_queue.empty())
    event = query._db_update_queue.get_nowait()
    query._db_update_queue.task_done()
    self.assertEqual(event, ("set_func_start", 0x1000, 0x1050, 0x1010))

  def test_set_func_start_skips_when_unchanged(self):
    pfn = mock.MagicMock()
    pfn.start_ea = 0x1000
    pfn.end_ea = 0x1050

    self.hooks.set_func_start(pfn, 0x1000)
    self.assertTrue(query._db_update_queue.empty())

  def test_set_func_end_enqueues_when_changed(self):
    pfn = mock.MagicMock()
    pfn.start_ea = 0x1000
    pfn.end_ea = 0x1050

    self.hooks.set_func_end(pfn, 0x1040)
    self.assertFalse(query._db_update_queue.empty())
    event = query._db_update_queue.get_nowait()
    query._db_update_queue.task_done()
    self.assertEqual(event, ("set_func_end", 0x1000, 0x1050, 0x1040))

  def test_set_func_end_skips_when_unchanged(self):
    pfn = mock.MagicMock()
    pfn.start_ea = 0x1000
    pfn.end_ea = 0x1050

    self.hooks.set_func_end(pfn, 0x1050)
    self.assertTrue(query._db_update_queue.empty())

  @mock.patch.object(query, "_get_func_info")
  def test_func_added_enqueues_with_bounds(self, mock_get_info):
    dummy_info = query.FuncInfo(
        0x1000, 0x1050, "test_func", None, None, 0x50, 0
    )
    mock_get_info.return_value = dummy_info

    pfn = mock.MagicMock()
    pfn.start_ea = 0x1000
    pfn.end_ea = 0x1050

    self.hooks.func_added(pfn)
    self.assertFalse(query._db_update_queue.empty())
    event = query._db_update_queue.get_nowait()
    query._db_update_queue.task_done()
    self.assertEqual(event, ("func_added", 0x1000, 0x1050, dummy_info))

  def test_func_deleted_enqueues_ea(self):
    self.hooks.func_deleted(0x1000)
    self.assertFalse(query._db_update_queue.empty())
    event = query._db_update_queue.get_nowait()
    query._db_update_queue.task_done()
    self.assertEqual(event, ("func_deleted", 0x1000))

  @mock.patch.object(query, "_get_func_info")
  def test_func_updated_enqueues_info(self, mock_get_info):
    dummy_info = query.FuncInfo(
        0x1000, 0x1050, "renamed_func", None, None, 0x50, 0
    )
    mock_get_info.return_value = dummy_info

    pfn = mock.MagicMock()
    pfn.start_ea = 0x1000
    pfn.end_ea = 0x1050

    self.hooks.func_updated(pfn)
    self.assertFalse(query._db_update_queue.empty())
    event = query._db_update_queue.get_nowait()
    query._db_update_queue.task_done()
    self.assertEqual(event, ("func_updated", 0x1000, dummy_info))


class TestDBWorkerFunctionAndXrefSync(unittest.TestCase):
  """Tests verifying SQLite database updates by _db_worker for function and xref events."""

  @classmethod
  def setUpClass(cls):
    super().setUpClass()
    _drain_queue()
    cls.conn = query._get_rw_conn()
    cls.worker = threading.Thread(target=query._db_worker, daemon=True)
    cls.worker.start()

  @classmethod
  def tearDownClass(cls):
    query._db_update_queue.put(("quit",))
    cls.worker.join(timeout=2.0)
    super().tearDownClass()

  def setUp(self):
    super().setUp()
    with query._db_write_lock:
      self.conn.execute("DROP TABLE IF EXISTS functions")
      self.conn.execute("DROP TABLE IF EXISTS xrefs")
      self.conn.execute("""
        CREATE TABLE functions (
          start_ea INTEGER PRIMARY KEY,
          end_ea INTEGER,
          name TEXT,
          demangled_name TEXT,
          prototype TEXT,
          size INTEGER,
          is_lib INTEGER
        )
      """)
      self.conn.execute("""
        CREATE TABLE xrefs (
          from_ea INTEGER,
          to_ea INTEGER,
          type TEXT,
          from_function_ea INTEGER,
          UNIQUE(from_ea, to_ea, type)
        )
      """)
      query._created_tables.add("functions")
      query._created_tables.add("xrefs")

  def test_set_func_start_shrink_and_expand(self):
    # Seed initial function 0x1000..0x1050 and xrefs
    self.conn.execute(
        "INSERT INTO functions VALUES (4096, 4176, 'func1', NULL, NULL, 80, 0)"
    )
    self.conn.execute("INSERT INTO xrefs VALUES (4100, 8000, 'call', 4096)")
    self.conn.execute("INSERT INTO xrefs VALUES (4120, 8000, 'call', 4096)")
    self.conn.execute("INSERT INTO xrefs VALUES (4150, 8000, 'call', 4096)")

    # Shrink start from 4096 to 4110
    query._db_update_queue.put(("set_func_start", 4096, 4176, 4110))
    query._db_update_queue.join()

    cursor = self.conn.cursor()
    cursor.execute("SELECT start_ea, end_ea, size FROM functions")
    row = cursor.fetchone()
    self.assertEqual(row, (4110, 4176, 66))

    # Verify xrefs: 4100 is outside, 4120 & 4150 are inside
    cursor.execute(
        "SELECT from_ea, from_function_ea FROM xrefs ORDER BY from_ea"
    )
    rows = cursor.fetchall()
    self.assertEqual(rows, [(4100, None), (4120, 4110), (4150, 4110)])

    # Expand start back to 4096
    query._db_update_queue.put(("set_func_start", 4110, 4176, 4096))
    query._db_update_queue.join()

    cursor.execute("SELECT start_ea, end_ea, size FROM functions")
    self.assertEqual(cursor.fetchone(), (4096, 4176, 80))

    cursor.execute(
        "SELECT from_ea, from_function_ea FROM xrefs ORDER BY from_ea"
    )
    rows = cursor.fetchall()
    self.assertEqual(rows, [(4100, 4096), (4120, 4096), (4150, 4096)])

  def test_set_func_end_shrink_and_expand(self):
    self.conn.execute(
        "INSERT INTO functions VALUES (4096, 4176, 'func1', NULL, NULL, 80, 0)"
    )
    self.conn.execute("INSERT INTO xrefs VALUES (4100, 8000, 'call', 4096)")
    self.conn.execute("INSERT INTO xrefs VALUES (4120, 8000, 'call', 4096)")
    self.conn.execute("INSERT INTO xrefs VALUES (4170, 8000, 'call', 4096)")

    # Shrink end from 4176 to 4150
    query._db_update_queue.put(("set_func_end", 4096, 4176, 4150))
    query._db_update_queue.join()

    cursor = self.conn.cursor()
    cursor.execute("SELECT start_ea, end_ea, size FROM functions")
    self.assertEqual(cursor.fetchone(), (4096, 4150, 54))

    # xref at 4170 should now have from_function_ea = NULL
    cursor.execute(
        "SELECT from_ea, from_function_ea FROM xrefs ORDER BY from_ea"
    )
    rows = cursor.fetchall()
    self.assertEqual(rows, [(4100, 4096), (4120, 4096), (4170, None)])

    # Expand end back to 4176
    query._db_update_queue.put(("set_func_end", 4096, 4150, 4176))
    query._db_update_queue.join()

    cursor.execute("SELECT start_ea, end_ea, size FROM functions")
    self.assertEqual(cursor.fetchone(), (4096, 4176, 80))

    cursor.execute(
        "SELECT from_ea, from_function_ea FROM xrefs ORDER BY from_ea"
    )
    rows = cursor.fetchall()
    self.assertEqual(rows, [(4100, 4096), (4120, 4096), (4170, 4096)])

  def test_func_updated_only_updates_functions(self):
    self.conn.execute(
        "INSERT INTO functions VALUES (4096, 4176, 'old_name', NULL, NULL, 80,"
        " 0)"
    )
    self.conn.execute("INSERT INTO xrefs VALUES (4100, 8000, 'call', 4096)")

    info = query.FuncInfo(
        4096, 4176, "new_name", "demangled", "void new_name()", 80, 0
    )
    query._db_update_queue.put(("func_updated", 4096, info))
    query._db_update_queue.join()

    cursor = self.conn.cursor()
    cursor.execute("SELECT name, demangled_name, prototype FROM functions")
    self.assertEqual(
        cursor.fetchone(), ("new_name", "demangled", "void new_name()")
    )

    # Xrefs untouched
    cursor.execute("SELECT from_ea, from_function_ea FROM xrefs")
    self.assertEqual(cursor.fetchall(), [(4100, 4096)])

  def test_func_deleted_clears_functions_and_xrefs(self):
    self.conn.execute(
        "INSERT INTO functions VALUES (4096, 4176, 'func1', NULL, NULL, 80, 0)"
    )
    self.conn.execute("INSERT INTO xrefs VALUES (4100, 8000, 'call', 4096)")
    self.conn.execute("INSERT INTO xrefs VALUES (4150, 8000, 'call', 4096)")

    query._db_update_queue.put(("func_deleted", 4096))
    query._db_update_queue.join()

    cursor = self.conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM functions WHERE start_ea = 4096")
    self.assertEqual(cursor.fetchone()[0], 0)

    cursor.execute(
        "SELECT from_ea, from_function_ea FROM xrefs ORDER BY from_ea"
    )
    rows = cursor.fetchall()
    self.assertEqual(rows, [(4100, None), (4150, None)])

  def test_func_added_inserts_function_and_attaches_xrefs(self):
    # xrefs initially detached (from_function_ea is NULL)
    self.conn.execute("INSERT INTO xrefs VALUES (4100, 8000, 'call', NULL)")
    self.conn.execute("INSERT INTO xrefs VALUES (4150, 8000, 'call', NULL)")
    self.conn.execute("INSERT INTO xrefs VALUES (5000, 8000, 'call', NULL)")

    info = query.FuncInfo(4096, 4176, "added_func", None, None, 80, 0)
    query._db_update_queue.put(("func_added", 4096, 4176, info))
    query._db_update_queue.join()

    cursor = self.conn.cursor()
    cursor.execute("SELECT start_ea, end_ea, name FROM functions")
    self.assertEqual(cursor.fetchone(), (4096, 4176, "added_func"))

    # Only xrefs in [4096, 4176) should be attached to 4096
    cursor.execute(
        "SELECT from_ea, from_function_ea FROM xrefs ORDER BY from_ea"
    )
    rows = cursor.fetchall()
    self.assertEqual(rows, [(4100, 4096), (4150, 4096), (5000, None)])

  def test_func_boundary_straddling_sign_boundary(self):
    # Unsigned addresses crossing 0x8000_0000_0000_0000 (signed positive -> negative)
    # start: 0x7FFF_FFFF_FFFF_FFF0, end: 0x8000_0000_0000_0010 (size = 32 bytes)
    start_ea = 0x7FFFFFFFFFFFFFF0
    end_ea = 0x8000000000000010
    signed_start = query._to_signed_64(start_ea)
    signed_end = query._to_signed_64(end_ea)

    self.assertGreaterEqual(signed_start, 0)
    self.assertLess(signed_end, 0)

    # 1. xref below function (0x1000)
    ea_below = query._to_signed_64(0x1000)
    # 2. xref inside function (positive half)
    ea_in_pos = query._to_signed_64(0x7FFFFFFFFFFFFFF5)
    # 3. xref inside function (negative half)
    ea_in_neg = query._to_signed_64(0x8000000000000005)
    # 4. xref above function (0x8000_0000_0000_0020)
    ea_above = query._to_signed_64(0x8000000000000020)

    self.conn.execute("INSERT INTO xrefs VALUES (?, 8000, 'call', NULL)", (ea_below,))
    self.conn.execute("INSERT INTO xrefs VALUES (?, 8000, 'call', NULL)", (ea_in_pos,))
    self.conn.execute("INSERT INTO xrefs VALUES (?, 8000, 'call', NULL)", (ea_in_neg,))
    self.conn.execute("INSERT INTO xrefs VALUES (?, 8000, 'call', NULL)", (ea_above,))

    info = query.FuncInfo(signed_start, signed_end, "straddle_func", None, None, 32, 0)
    query._db_update_queue.put(("func_added", start_ea, end_ea, info))
    query._db_update_queue.join()

    cursor = self.conn.cursor()
    cursor.execute("SELECT from_ea, from_function_ea FROM xrefs")
    xref_map = dict(cursor.fetchall())

    self.assertIsNone(xref_map[ea_below])
    self.assertEqual(xref_map[ea_in_pos], signed_start)
    self.assertEqual(xref_map[ea_in_neg], signed_start)
    self.assertIsNone(xref_map[ea_above])



class TestDBUpdateIDPHooks(unittest.TestCase):
  """Tests verifying that DBUpdateIDPHooks filters and pushes events."""

  def setUp(self):
    super().setUp()
    _drain_queue()
    sys.modules["idaapi"].fl_F = 21
    self.hooks = query.DBUpdateIDPHooks()

  def tearDown(self):
    _drain_queue()
    super().tearDown()

  def test_ev_add_cref_skips_flow(self):
    res = self.hooks.ev_add_cref(_from=0x1000, to=0x1004, xref_type=21)
    self.assertEqual(res, 0)
    self.assertTrue(query._db_update_queue.empty())

  @mock.patch.object(query.helper, "get_func_bounds")
  def test_ev_add_cref_enqueues_non_flow(self, mock_bounds):
    mock_pfn = mock.MagicMock()
    mock_pfn.start_ea = 0x1000
    mock_bounds.return_value = mock_pfn

    res = self.hooks.ev_add_cref(_from=0x1010, to=0x2000, xref_type=17)
    self.assertEqual(res, 0)
    self.assertFalse(query._db_update_queue.empty())
    event = query._db_update_queue.get_nowait()
    query._db_update_queue.task_done()
    self.assertEqual(event, ("cref_added", 0x1010, 0x2000, 17, 0x1000))


if __name__ == "__main__":
  unittest.main()

