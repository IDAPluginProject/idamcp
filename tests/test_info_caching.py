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


"""Unit tests for the info module caching mechanisms."""

import sys
import unittest
from unittest import mock

# Mock IDA modules
MOCKED_MODULES = [
    "ida_bytes",
    "ida_idp",
    "ida_funcs",
    "ida_frame",
    "ida_gdl",
    "ida_hexrays",
    "ida_kernwin",
    "ida_moves",
    "ida_nalt",
    "ida_segment",
    "ida_typeinf",
    "ida_xref",
    "idaapi",
    "ida_ida",
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

# Import the module under test
# pylint: disable=g-import-not-at-top
from ida_mcp.tools import info
from ida_mcp.utils.caching import IteratorCache

# pylint: enable=g-import-not-at-top

for _fn in ["list_functions", "list_globals", "list_imports", "list_strings"]:
  if hasattr(info, _fn):
    setattr(
        info, _fn, getattr(getattr(info, _fn), "sync_call", getattr(info, _fn))
    )


class MockStringsList:

  def __init__(self, items):
    self.items = items
    self.size = len(items)

  def __iter__(self):
    return iter(self.items)


class TestInfoCaching(unittest.TestCase):
  """Tests for the caching logic in info module."""

  def setUp(self):
    super().setUp()
    # Reset caches before each test
    # pylint: disable=protected-access
    info._function_iterator_cache = IteratorCache()
    info._global_iterator_cache = IteratorCache()
    info._import_iterator_cache = IteratorCache()
    info._string_iterator_cache = IteratorCache()
    # pylint: enable=protected-access

    # Setup common mocks
    # Generate 100 mock functions: 100, 200, ..., 10000
    self.mock_functions = [i * 100 for i in range(1, 101)]
    # Use side_effect to return a new iterator each time the function is called
    sys.modules["idautils"].Functions.side_effect = lambda: iter(
        self.mock_functions
    )
    sys.modules["ida_funcs"].get_func_ea_by_num.side_effect = (
        lambda n: self.mock_functions[n]
    )
    sys.modules["idaapi"].get_func_name.side_effect = lambda x: f"func_{x}"
    sys.modules["idc"].get_func_attr.return_value = 0x10  # func_size
    sys.modules["idaapi"].get_func_qty.return_value = 100
    sys.modules["ida_funcs"].get_func_qty.return_value = 100
    sys.modules["idaapi"].get_nlist_size.return_value = 200
    sys.modules["idaapi"].get_strlist_qty.return_value = 100

  def test_list_functions_pagination(self):
    """Test paginating through list_functions."""
    # 1. First call: get first 20 functions
    count = 20
    page1 = info.list_functions(offset=0, count=count, regex_filter="")
    self.assertEqual(len(page1["data"]), count)
    self.assertEqual(page1["data"][0]["name"], "func_100")
    self.assertEqual(page1["data"][-1]["name"], f"func_{count * 100}")
    self.assertEqual(page1["next_offset"], count)

    # Verify cache has the iterator for the next page
    # Key is (next_offset, regex_filter, regex_flags) -> (20, "", "IGNORECASE")
    # pylint: disable=protected-access
    self.assertIn((count, "", "IGNORECASE"), info._function_iterator_cache)

    # 2. Second call: get next 20 functions
    page2 = info.list_functions(offset=count, count=count, regex_filter="")
    self.assertEqual(len(page2["data"]), count)
    self.assertEqual(page2["data"][0]["name"], f"func_{(count + 1) * 100}")
    self.assertEqual(page2["data"][-1]["name"], f"func_{(count * 2) * 100}")
    self.assertEqual(page2["next_offset"], count * 2)

    # Verify old cache entry is gone (pop was used) and new one exists
    self.assertNotIn((count, "", "IGNORECASE"), info._function_iterator_cache)
    self.assertIn((count * 2, "", "IGNORECASE"), info._function_iterator_cache)
    # pylint: enable=protected-access

  def test_list_functions_regex_filter(self):
    """Test list_functions with regex filter."""
    # Setup functions with mixed names
    # Generate 100 functions, every 10th one matches "match"
    mock_funcs = list(range(100))
    sys.modules["idautils"].Functions.side_effect = lambda: iter(mock_funcs)

    def get_name(x):
      if x % 10 == 0:
        return f"match_{x}"
      return f"ignore_{x}"

    sys.modules["idaapi"].get_func_name.side_effect = get_name

    # Filter for "match"
    # Should match 0, 10, 20, ..., 90 (10 items)
    page = info.list_functions(offset=0, count=100, regex_filter="match")
    self.assertEqual(len(page["data"]), 10)
    self.assertEqual(page["data"][0]["name"], "match_0")
    self.assertEqual(page["data"][-1]["name"], "match_90")
    self.assertNotIn("next_offset", page)

  def test_list_functions_pagination_with_filter(self):
    """Test paginating through list_functions with a regex filter."""
    # Generate 100 functions.
    # We want enough matches to span multiple pages.
    # Let's say matches are: 0, 1, 2, ..., 49 (first 50) match "match"
    # 50..99 match "ignore"
    mock_funcs = list(range(100))
    sys.modules["idautils"].Functions.side_effect = lambda: iter(mock_funcs)

    def get_name(x):
      if x < 50:
        return f"match_{x}"
      return f"ignore_{x}"

    sys.modules["idaapi"].get_func_name.side_effect = get_name

    # Page 1: Get first 20 matches
    page1 = info.list_functions(offset=0, count=20, regex_filter="match")
    self.assertEqual(len(page1["data"]), 20)
    self.assertEqual(page1["data"][0]["name"], "match_0")
    self.assertEqual(page1["data"][-1]["name"], "match_19")
    self.assertEqual(page1["next_offset"], 20)

    # Page 2: Get next 20 matches
    page2 = info.list_functions(offset=20, count=20, regex_filter="match")
    self.assertEqual(len(page2["data"]), 20)
    self.assertEqual(page2["data"][0]["name"], "match_20")
    self.assertEqual(page2["data"][-1]["name"], "match_39")
    self.assertEqual(page2["next_offset"], 40)

    # Page 3: Get remaining 10 matches (total 50 matches)
    page3 = info.list_functions(offset=40, count=20, regex_filter="match")
    self.assertEqual(len(page3["data"]), 10)
    self.assertEqual(page3["data"][0]["name"], "match_40")
    self.assertEqual(page3["data"][-1]["name"], "match_49")
    self.assertNotIn("next_offset", page3)

  def test_list_globals_regex_filter(self):
    """Test list_globals with regex filter."""
    # Generate 100 globals
    # Even indices -> "match_varX", Odd -> "ignore_varX"
    mock_globals = [
        (i * 4, f"match_var{i}" if i % 2 == 0 else f"ignore_var{i}")
        for i in range(100)
    ]
    sys.modules["idautils"].Names.side_effect = lambda: iter(mock_globals)
    sys.modules["idaapi"].is_func.return_value = False
    sys.modules["idaapi"].get_flags.return_value = 0

    # Filter for "match" -> Should get 50 items (indices 0, 2, 4...)
    page = info.list_globals(offset=0, count=100, regex_filter="match")
    self.assertEqual(len(page["data"]), 50)
    self.assertEqual(page["data"][0]["name"], "match_var0")
    self.assertEqual(page["data"][1]["name"], "match_var2")
    self.assertNotIn("next_offset", page)

  def test_list_globals_pagination(self):
    """Test paginating through list_globals."""
    # Generate 100 globals
    mock_globals = [(i * 4, f"g_var{i}") for i in range(100)]
    sys.modules["idautils"].Names.side_effect = lambda: iter(mock_globals)
    sys.modules["idaapi"].is_func.return_value = False
    sys.modules["idaapi"].get_flags.return_value = 0

    # 1. Page 1
    count = 20
    page1 = info.list_globals(offset=0, count=count, regex_filter="")
    self.assertEqual(len(page1["data"]), count)
    self.assertEqual(page1["data"][0]["name"], "g_var0")
    self.assertEqual(page1["data"][-1]["name"], f"g_var{count-1}")
    self.assertEqual(page1["next_offset"], count)
    # pylint: disable=protected-access
    self.assertIn((count, ""), info._global_iterator_cache)
    # pylint: enable=protected-access

    # 2. Page 2
    page2 = info.list_globals(offset=count, count=count, regex_filter="")
    self.assertEqual(len(page2["data"]), count)
    self.assertEqual(page2["data"][0]["name"], f"g_var{count}")
    self.assertEqual(page2["next_offset"], count * 2)

  def test_list_imports_pagination(self):
    """Test paginating through list_imports."""
    # Mock ida_nalt imports
    sys.modules["ida_nalt"].get_import_module_qty.return_value = 1
    sys.modules["ida_nalt"].get_import_module_name.return_value = "kernel32.dll"

    # Generate 100 imports
    total_imports = 100

    # pylint: disable=unused-argument
    def mock_enum_import_names(idx, callback):
      for i in range(total_imports):
        # ea, name, ordinal
        if not callback(0x2000 + i * 4, f"Import_{i}", i):
          break
      return total_imports

    # pylint: enable=unused-argument

    sys.modules["ida_nalt"].enum_import_names.side_effect = (
        mock_enum_import_names
    )

    # 1. Page 1
    count = 20
    page1 = info.list_imports(offset=0, count=count)
    self.assertEqual(len(page1["data"]), count)
    self.assertEqual(page1["data"][0]["imported_name"], "Import_0")
    self.assertEqual(page1["data"][-1]["imported_name"], f"Import_{count-1}")
    self.assertEqual(page1["next_offset"], count)
    # pylint: disable=protected-access
    self.assertIn((count,), info._import_iterator_cache)
    # pylint: enable=protected-access

    # 2. Page 2
    page2 = info.list_imports(offset=count, count=count)
    self.assertEqual(len(page2["data"]), count)
    self.assertEqual(page2["data"][0]["imported_name"], f"Import_{count}")
    self.assertEqual(page2["next_offset"], count * 2)

  def test_list_strings_pagination(self):
    """Test paginating through list_strings."""

    # Mock idautils.Strings()
    class MockStringItem:

      def __init__(self, ea, s):
        self.ea = ea
        self.length = len(s)
        self.s = s

      def __str__(self):
        return self.s

    # Generate 100 strings
    mock_strings = [
        MockStringItem(0x3000 + i * 16, f"string_{i}") for i in range(100)
    ]
    sys.modules["idautils"].Strings.side_effect = lambda: MockStringsList(
        mock_strings
    )

    # 1. Page 1
    count = 20
    page1 = info.list_strings(offset=0, count=count, regex_filter="")
    self.assertEqual(len(page1["data"]), count)
    self.assertEqual(page1["data"][0]["string"], "string_0")
    self.assertEqual(page1["data"][-1]["string"], f"string_{count-1}")
    self.assertEqual(page1["next_offset"], count)
    # pylint: disable=protected-access
    self.assertIn((count, "", "IGNORECASE"), info._string_iterator_cache)
    # pylint: enable=protected-access

    # 2. Page 2
    page2 = info.list_strings(offset=count, count=count, regex_filter="")
    self.assertEqual(len(page2["data"]), count)
    self.assertEqual(page2["data"][0]["string"], f"string_{count}")
    self.assertEqual(page2["next_offset"], count * 2)

  def test_list_strings_regex_filter(self):
    """Test list_strings with regex filter."""

    # Mock idautils.Strings()
    class MockStringItem:

      def __init__(self, ea, s):
        self.ea = ea
        self.length = len(s)
        self.s = s

      def __str__(self):
        return self.s

    # Generate 100 strings.
    # 0..9 -> "secret_0".. "secret_9"
    # 10..99 -> "public_10".. "public_99"
    mock_strings = []
    for i in range(100):
      s_val = f"secret_{i}" if i < 10 else f"public_{i}"
      mock_strings.append(MockStringItem(0x3000 + i, s_val))

    sys.modules["idautils"].Strings.side_effect = lambda: MockStringsList(
        mock_strings
    )

    # Filter for "secret" -> Should get 10 items
    page = info.list_strings(offset=0, count=100, regex_filter="secret")
    self.assertEqual(len(page["data"]), 10)
    self.assertEqual(page["data"][0]["string"], "secret_0")
    self.assertEqual(page["data"][-1]["string"], "secret_9")
    self.assertNotIn("next_offset", page)

  def test_list_functions_cache_eviction_simulation(self):
    """Test that if we request an offset that is NOT in cache, it restarts generation and skips."""
    # Request offset 50 directly (simulating cache eviction or new session)
    # It should create a new generator, skip 50 items, and return the next
    offset = 50
    page = info.list_functions(offset=offset, count=1, regex_filter="")

    self.assertEqual(len(page["data"]), 1)
    # mock_functions are 100, 200, ...
    # index 50 corresponds to func_5100 (since 0-based index 50 is the 51st
    # item).
    # Wait, mock_functions[50] is (50+1)*100 = 5100
    expected_name = f"func_{(offset + 1) * 100}"
    self.assertEqual(page["data"][0]["name"], expected_name)
    self.assertEqual(page["next_offset"], offset + 1)


if __name__ == "__main__":
  unittest.main()
