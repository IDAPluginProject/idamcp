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

"""Checks the gateway's advertised MCP metadata against a golden file.

See dump_mcp_metadata.py for what is captured. No IDA installation is needed.
"""

import difflib
import json
import pathlib
import subprocess
import sys
import tempfile
from typing import Any
import unittest

_TESTS_DIR = pathlib.Path(__file__).resolve().parent
_DUMP_SCRIPT = _TESTS_DIR / "dump_mcp_metadata.py"
_GOLDEN_PATH = _TESTS_DIR / "golden_mcp_metadata.json"
_DUMP_TIMEOUT_SECONDS = 120
_MAX_DIFF_LINES = 200

# Lists in the dump and the field that identifies each entry.
_SECTION_KEYS = (
    ("tools", "name"),
    ("resources", "uri"),
    ("resource_templates", "uriTemplate"),
    ("prompts", "name"),
)


def _to_lines(data: Any) -> list[str]:
  return json.dumps(
      data, indent=2, sort_keys=True, ensure_ascii=False
  ).splitlines()


def _describe_mismatch(expected: Any, actual: Any) -> str:
  """Summarizes added/removed entries, followed by a unified diff."""
  lines = [f"Gateway MCP metadata differs from {_GOLDEN_PATH.name}."]
  for section, key in _SECTION_KEYS:
    old = {entry[key] for entry in expected.get(section, [])}
    new = {entry[key] for entry in actual.get(section, [])}
    if added := sorted(new - old):
      lines.append(f"{section} added: {', '.join(added)}")
    if removed := sorted(old - new):
      lines.append(f"{section} removed: {', '.join(removed)}")

  diff = list(
      difflib.unified_diff(
          _to_lines(expected),
          _to_lines(actual),
          fromfile=_GOLDEN_PATH.name,
          tofile="current gateway",
          lineterm="",
      )
  )
  if len(diff) > _MAX_DIFF_LINES:
    omitted = len(diff) - _MAX_DIFF_LINES
    diff = diff[:_MAX_DIFF_LINES] + [f"... {omitted} more diff lines"]
  lines.extend(diff)
  lines.append(
      "If the change is intended, regenerate the golden file with"
      " `python3 tests/dump_mcp_metadata.py` and commit it."
  )
  return "\n".join(lines)


class McpMetadataTest(unittest.TestCase):
  """Compares the gateway's MCP metadata with golden_mcp_metadata.json."""

  def test_metadata_matches_golden_file(self):
    """Test that tools, resources, prompts and server info are unchanged."""
    # A fresh interpreter is required: gateway.forward loads the config and
    # registers tools at import time, and other test modules import it with
    # whatever config is present on the machine.
    with tempfile.TemporaryDirectory() as tmp_dir:
      output_path = pathlib.Path(tmp_dir) / "mcp_metadata.json"
      proc = subprocess.run(
          [sys.executable, str(_DUMP_SCRIPT), str(output_path)],
          capture_output=True,
          text=True,
          timeout=_DUMP_TIMEOUT_SECONDS,
          check=False,
      )
      if proc.returncode != 0:
        self.fail(
            f"{_DUMP_SCRIPT.name} exited with {proc.returncode}:\n{proc.stderr}"
        )
      actual = json.loads(output_path.read_text(encoding="utf-8"))

    expected = json.loads(_GOLDEN_PATH.read_text(encoding="utf-8"))
    if actual != expected:
      self.fail(_describe_mismatch(expected, actual))


if __name__ == "__main__":
  unittest.main()
