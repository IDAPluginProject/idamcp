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

"""Unit tests for installer server configuration and backups in install.py."""

import json
import pathlib
import tempfile
import unittest
from unittest import mock

import install

try:
  import tomllib
except ImportError:
  try:
    import tomli as tomllib
  except ImportError:
    tomllib = None

try:
  import tomli_w
except ImportError:
  tomli_w = None


class TestInstallServer(unittest.TestCase):
  """Tests for install_server in install.py."""

  def setUp(self):
    self.temp_dir = tempfile.TemporaryDirectory()
    self.home_path = pathlib.Path(self.temp_dir.name)
    self.env_patcher = mock.patch.dict(
        "os.environ", {"VIRTUAL_ENV": "/fake/venv"}
    )
    self.env_patcher.start()
    self.isatty_patcher = mock.patch("sys.stdin.isatty", return_value=False)
    self.isatty_patcher.start()

  def tearDown(self):
    self.isatty_patcher.stop()
    self.env_patcher.stop()
    self.temp_dir.cleanup()

  def test_json_install_new_file(self):
    """Test installing server when config file does not exist."""
    with mock.patch("pathlib.Path.home", return_value=self.home_path):
      install.install_server("gemini")

    settings_path = self.home_path / ".gemini" / "settings.json"
    self.assertTrue(settings_path.exists())
    with open(settings_path, "r") as f:
      data = json.load(f)
    self.assertIn("mcpServers", data)
    self.assertIn("idamcp", data["mcpServers"])

    # No backup should be created since original did not exist
    backups = list(settings_path.parent.glob("*.bak"))
    self.assertEqual(len(backups), 0)

  def test_json_install_existing_valid_file_creates_backup(self):
    """Test installing server when valid config exists creates a timestamped backup."""
    settings_dir = self.home_path / ".gemini"
    settings_dir.mkdir(parents=True, exist_ok=True)
    settings_path = settings_dir / "settings.json"
    original_data = {
        "existing_key": "existing_value",
        "mcpServers": {"other_server": {"command": "other"}},
    }
    with open(settings_path, "w") as f:
      json.dump(original_data, f)

    with mock.patch("pathlib.Path.home", return_value=self.home_path):
      install.install_server("gemini")

    # Verify backup exists and contains original content
    backups = list(settings_dir.glob("settings.json.*.bak"))
    self.assertEqual(len(backups), 1)
    with open(backups[0], "r") as f:
      backup_data = json.load(f)
    self.assertEqual(backup_data, original_data)

    # Verify updated settings file contains both existing and new server
    with open(settings_path, "r") as f:
      updated_data = json.load(f)
    self.assertEqual(updated_data["existing_key"], "existing_value")
    self.assertIn("other_server", updated_data["mcpServers"])
    self.assertIn("idamcp", updated_data["mcpServers"])

  def test_json_install_existing_invalid_file_aborts_without_overwrite(self):
    """Test that install aborts and does not overwrite when JSON is invalid."""
    settings_dir = self.home_path / ".gemini"
    settings_dir.mkdir(parents=True, exist_ok=True)
    settings_path = settings_dir / "settings.json"
    invalid_json_content = "{\ninvalid json here: true,\n"
    with open(settings_path, "w") as f:
      f.write(invalid_json_content)

    with mock.patch("pathlib.Path.home", return_value=self.home_path):
      install.install_server("gemini")

    # Content should remain unchanged
    with open(settings_path, "r") as f:
      content = f.read()
    self.assertEqual(content, invalid_json_content)

    # No backup should be created since parsing failed
    backups = list(settings_dir.glob("*.bak"))
    self.assertEqual(len(backups), 0)

  def test_json_install_non_dict_aborts(self):
    """Test that install aborts if JSON root is not a dict (e.g. array)."""
    settings_dir = self.home_path / ".gemini"
    settings_dir.mkdir(parents=True, exist_ok=True)
    settings_path = settings_dir / "settings.json"
    with open(settings_path, "w") as f:
      json.dump(["item1", "item2"], f)

    with mock.patch("pathlib.Path.home", return_value=self.home_path):
      install.install_server("gemini")

    with open(settings_path, "r") as f:
      data = json.load(f)
    self.assertEqual(data, ["item1", "item2"])

  @unittest.skipIf(
      tomllib is None or tomli_w is None, "tomllib or tomli_w not installed"
  )
  def test_codex_install_existing_valid_file_creates_backup(self):
    """Test installing server for Codex with existing config creates timestamped backup."""
    settings_dir = self.home_path / ".codex"
    settings_dir.mkdir(parents=True, exist_ok=True)
    settings_path = settings_dir / "config.toml"
    original_data = {"existing_setting": 123}
    with open(settings_path, "wb") as f:
      tomli_w.dump(original_data, f)

    with mock.patch("pathlib.Path.home", return_value=self.home_path):
      install.install_server("codex")

    backups = list(settings_dir.glob("config.toml.*.bak"))
    self.assertEqual(len(backups), 1)
    with open(backups[0], "rb") as f:
      backup_data = tomllib.load(f)
    self.assertEqual(backup_data, original_data)

    with open(settings_path, "rb") as f:
      updated_data = tomllib.load(f)
    self.assertEqual(updated_data["existing_setting"], 123)
    self.assertIn("mcp_servers", updated_data)
    self.assertIn("idamcp", updated_data["mcp_servers"])

  @unittest.skipIf(
      tomllib is None or tomli_w is None, "tomllib or tomli_w not installed"
  )
  def test_codex_install_existing_invalid_file_aborts(self):
    """Test that install aborts and does not overwrite when TOML is invalid."""
    settings_dir = self.home_path / ".codex"
    settings_dir.mkdir(parents=True, exist_ok=True)
    settings_path = settings_dir / "config.toml"
    invalid_toml_content = "[[mcp_servers\ninvalid = = toml\n"
    with open(settings_path, "w") as f:
      f.write(invalid_toml_content)

    with mock.patch("pathlib.Path.home", return_value=self.home_path):
      install.install_server("codex")

    with open(settings_path, "r") as f:
      content = f.read()
    self.assertEqual(content, invalid_toml_content)

    backups = list(settings_dir.glob("*.bak"))
    self.assertEqual(len(backups), 0)

  @unittest.skipIf(
      tomllib is None or tomli_w is None, "tomllib or tomli_w not installed"
  )
  def test_codex_install_toml_1_0_features(self):
    """Test that modern TOML 1.0 features (like heterogeneous arrays) are parsed."""
    settings_dir = self.home_path / ".codex"
    settings_dir.mkdir(parents=True, exist_ok=True)
    settings_path = settings_dir / "config.toml"
    toml_1_0_content = 'model = "gpt-5.6"\nmixed_array = [1, "string", true]\n'
    with open(settings_path, "w") as f:
      f.write(toml_1_0_content)

    with mock.patch("pathlib.Path.home", return_value=self.home_path):
      install.install_server("codex")

    backups = list(settings_dir.glob("config.toml.*.bak"))
    self.assertEqual(len(backups), 1)

    with open(settings_path, "rb") as f:
      updated_data = tomllib.load(f)
    self.assertEqual(updated_data["model"], "gpt-5.6")
    self.assertEqual(updated_data["mixed_array"], [1, "string", True])
    self.assertIn("mcp_servers", updated_data)
    self.assertIn("idamcp", updated_data["mcp_servers"])

  @unittest.skipIf(
      tomllib is None or tomli_w is None, "tomllib or tomli_w not installed"
  )
  def test_codex_install_windows_path_keys(self):
    """Test that TOML literal strings with Windows paths (e.g.

    'C:\\Users\\...') are parsed.
    """
    settings_dir = self.home_path / ".codex"
    settings_dir.mkdir(parents=True, exist_ok=True)
    settings_path = settings_dir / "config.toml"
    toml_content = (
        'model = "gpt-5.6"\n\n'
        "[permissions.workspace.workspace_roots]\n"
        "'C:\\Users\\xxx\\workspace' = true\n"
    )
    with open(settings_path, "w", encoding="utf-8") as f:
      f.write(toml_content)

    with mock.patch("pathlib.Path.home", return_value=self.home_path):
      install.install_server("codex")

    backups = list(settings_dir.glob("config.toml.*.bak"))
    self.assertEqual(len(backups), 1)

    with open(settings_path, "rb") as f:
      updated_data = tomllib.load(f)
    self.assertEqual(updated_data["model"], "gpt-5.6")
    self.assertTrue(
        updated_data["permissions"]["workspace"]["workspace_roots"][
            r"C:\Users\xxx\workspace"
        ]
    )
    self.assertIn("mcp_servers", updated_data)
    self.assertIn("idamcp", updated_data["mcp_servers"])


if __name__ == "__main__":
  unittest.main()
