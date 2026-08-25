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

"""Frontend application for IDA MCP."""

import argparse
import asyncio
import glob
import json
import os
import pathlib
import sys
import threading
import time
import typing
import webbrowser

# Add project root to sys.path
root_dir = pathlib.Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
  sys.path.append(str(root_dir))

import fastapi  # pylint: disable=g-import-not-at-top
import fastapi.responses  # pylint: disable=g-import-not-at-top
from shared.rpc import RPCClient, RPCError
from pydantic import BaseModel  # pylint: disable=g-import-not-at-top
from shared.config import load_config  # pylint: disable=g-import-not-at-top
import uvicorn  # pylint: disable=g-import-not-at-top

app = fastapi.FastAPI()

# Load config to get registry dir
config = load_config()
REGISTRY_DIR = config["registry_dir"]


class RpcRequest(BaseModel):
  method: str
  params: typing.Dict[str, typing.Any] = {}


async def connect_client(info: typing.Dict[str, typing.Any]) -> RPCClient:
  client = RPCClient()
  if info.get("channel") == "tcp":
    await client.connect_tcp("127.0.0.1", int(info["address"]))
  elif info.get("channel") == "uds":
    await client.connect_uds(info["address"])
  else:
    raise ValueError(f"Unknown channel: {info.get('channel')}")
  return client


async def check_backend_alive(info: typing.Dict[str, typing.Any]) -> bool:
  client = None
  try:
    client = await connect_client(info)
    ret = await asyncio.wait_for(client.ping(), timeout=2.0)
    return ret
  except Exception:
    return False
  finally:
    if client:
      await client.close()


@app.get("/", response_class=fastapi.responses.HTMLResponse)
async def read_root():
  """Serve the index HTML."""
  html_path = pathlib.Path(__file__).parent / "index.html"
  if html_path.exists():
    with open(html_path) as f:
      return f.read()
  return "<h1>Frontend index.html not found</h1>"


@app.get("/api/backends")
async def get_backends():
  """List all available backends."""
  files = glob.glob(os.path.join(REGISTRY_DIR, "*.json"))
  backends = []
  for f in files:
    try:
      with open(f) as fd:
        data = json.load(fd)

      if await check_backend_alive(data):
        backends.append(data)
      else:
        # Backend is dead, try to clean up
        try:
          os.remove(f)
          print(f"Removed stale registry file: {f}")
        except OSError:
          pass

    except Exception as e:  # pylint: disable=broad-exception-caught
      print(f"Error reading/checking registry file {f}: {e}")
  return backends


@app.post("/api/rpc/{backend_name}")
async def call_rpc(backend_name: str, req: RpcRequest):
  """Forward an RPC call to a specific backend."""
  path = os.path.join(REGISTRY_DIR, f"{backend_name}.json")
  if not os.path.exists(path):
    raise fastapi.HTTPException(status_code=404, detail="Backend not found")

  try:
    with open(path) as f:
      info = json.load(f)
  except Exception as e:
    raise fastapi.HTTPException(
        status_code=500, detail="Failed to read backend info"
    ) from e

  client = None
  try:
    # Retry connection logic
    last_error = None
    for _ in range(5):
      try:
        client = await connect_client(info)
        break
      except Exception as e:  # pylint: disable=broad-exception-caught
        last_error = e
        await asyncio.sleep(0.1)

    if not client:
      raise last_error if last_error else Exception("Failed to connect")

    try:
      # Call the raw RPC method
      result = await client.call(method=req.method, params=req.params)

      # Format result to match FastMCP CallToolResult for frontend compatibility
      return {
          "content": [{"type": "text", "text": json.dumps(result)}],
          "isError": False,
      }
    except RPCError as e:
      return {
          "content": [{"type": "text", "text": str(e)}],
          "isError": True,
      }
    finally:
      await client.close()

  except Exception as e:
    raise fastapi.HTTPException(status_code=500, detail=str(e)) from e


def open_browser(port: int):
  time.sleep(3)  # Give uvicorn a moment to start
  url = f"http://127.0.0.1:{port}"
  webbrowser.open(url)


def main():
  parser = argparse.ArgumentParser(description="Start the security dashboard.")
  parser.add_argument(
      "--port",
      type=int,
      default=8080,
      help="Port to run the dashboard on.",
  )
  parser.add_argument(
      "--no-browser",
      action="store_true",
      help="Do not automatically open the browser.",
  )
  args = parser.parse_args()

  if not args.no_browser:
    threading.Thread(
        target=open_browser, args=(args.port,), daemon=True
    ).start()

  uvicorn.run(
      "frontend.security_dashboard:app",
      host="127.0.0.1",
      port=args.port,
  )


if __name__ == "__main__":
  main()
