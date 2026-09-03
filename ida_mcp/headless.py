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

"""Headless IDA Pro MCP Server."""

import argparse
import contextlib
import hashlib
import logging
import pathlib
import signal
import sys
import threading

# fmt: off
# idapro must go first to initialize idalib
try:
  import idapro  # pylint: disable=g-bad-import-order
except ImportError:
  sys.exit("[Error] Can't import idapro, please install idalib first.")

import idaapi
from ida_mcp.core import ida_thread
from ida_mcp.server import mcp_server_thread
# fmt: on


logger = logging.getLogger(__name__)


def _server_thread(hash_str: str) -> None:
  logger.info("Starting MCP server...")
  ida_thread.wait_for_loop_event()
  try:
    mcp_server_thread(hash_str)
  finally:
    logger.info("Server stopped, closing database...")
    ida_thread.stop()


def main():
  parser = argparse.ArgumentParser(description="Headless IDA Pro MCP Server")
  parser.add_argument(
      "input_path", type=pathlib.Path, help="Path to the binary file to analyze"
  )
  args = parser.parse_args()

  # Configure logging
  logging.basicConfig(level=logging.INFO)

  if not args.input_path.exists():
    logger.error("Input file not found: %s", args.input_path)
    sys.exit(1)

  logger.info("Initializing idalib and opening %s...", args.input_path)

  try:
    ret = idapro.open_database(str(args.input_path), run_auto_analysis=True)
    if ret != 0:
      logger.error("Failed to open database, error code: %#x", ret)
      sys.exit(1)
  except Exception as e:  # pylint: disable=broad-exception-caught
    logger.exception("Failed to open database, exception: %s", e)
    sys.exit(1)

  idb_path = None
  with contextlib.suppress(Exception):
    idb_path = idaapi.get_path(idaapi.PATH_TYPE_IDB)

  if not idb_path:
    # Fallback
    idb_path = str(args.input_path)
  idaapi.idb_path = idb_path  # type: ignore
  idaapi.is_headless = True  # type: ignore
  hash_str = hashlib.sha256(idb_path.encode()).hexdigest()[-8:]

  logger.info("Session identifier: %s", hash_str)
  original_handlers = {}

  # Setup signal handlers for clean exit
  def signal_handler(sig, frame):
    logger.info("Received signal: %d, Shutting down...", sig)
    ida_thread.stop()
    handler = original_handlers.get(sig, None)
    if handler and callable(handler):
      handler(sig, frame)

  for sig_name in ("SIGINT", "SIGTERM", "SIGBREAK"):
    if (sig := getattr(signal, sig_name, None)) != None:
      try:
        original_handlers[sig] = signal.signal(sig, signal_handler)
      except Exception as e:  # pylint: disable=broad-exception-caught
        logger.exception("Could not register handler for signal %s: %s", sig, e)

  server_thread = threading.Thread(
      target=_server_thread,
      args=(hash_str,),
      daemon=True,
  )
  server_thread.start()
  try:
    ida_thread.loop()
  finally:
    try:
      idapro.close_database()
    except Exception as e:  # pylint: disable=broad-exception-caught
      logger.exception("Error closing database: %s", e)


if __name__ == "__main__":
  main()
