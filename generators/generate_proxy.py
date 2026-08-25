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

"""Generates a proxy for the IDA MCP."""

import ast
import glob
import os

from tree_sitter import Language
from tree_sitter import Parser
from tree_sitter import Query
from tree_sitter import QueryCursor
import tree_sitter_python as tspython


def _extract_arg_names(source_code, captures):
  """Extracts argument names from captures."""
  arg_names = []
  if 'params' in captures:
    params_node = captures['params'][0]
    for child in params_node.children:
      if child.type == 'identifier':
        arg_names.append(
            source_code[child.start_byte : child.end_byte].decode()
        )
      elif (
          child.type == 'typed_parameter'
          or child.type == 'default_parameter'
          or child.type == 'typed_default_parameter'
      ):
        if child.child_count > 0 and child.children[0].type == 'identifier':
          arg_names.append(
              source_code[
                  child.children[0].start_byte : child.children[0].end_byte
              ].decode()
          )
  return arg_names


def _extract_decorators_and_jsonrpc(source_code, func_node):
  """Extracts decorators and jsonrpc description."""
  decorators = []
  jsonrpc_description = ''
  if func_node.parent and func_node.parent.type == 'decorated_definition':
    start_byte = func_node.parent.start_byte
    for child in func_node.parent.children:
      if child.type == 'decorator':
        dec_text = (
            source_code[child.start_byte : child.end_byte].decode().strip()
        )
        decorators.append(dec_text)

        if dec_text.startswith('@jsonrpc'):
          jsonrpc_description = dec_text[8:]
  else:
    start_byte = func_node.start_byte
  return decorators, jsonrpc_description, start_byte


def _extract_prototype(source_code, func_node, body_node, start_byte):
  """Extracts prototype text."""
  end_byte = body_node.start_byte
  for child in func_node.children:
    if child.type == ':':
      end_byte = child.end_byte
      break

  raw_proto = source_code[start_byte:end_byte]
  prototype_text = raw_proto.decode('utf-8').strip()
  prototype_text_without_decorator = source_code[
      func_node.start_byte : end_byte
  ].decode()
  return prototype_text, prototype_text_without_decorator


def _extract_docstring(source_code, body_node):
  """Extracts docstring."""
  docstring = None
  for child in body_node.children:
    if child.type == 'comment':
      continue
    if child.type == 'expression_statement':
      string_node = None
      for subchild in child.children:
        if subchild.type == 'string':
          string_node = subchild
          break
      if string_node:
        raw_docstring = source_code[
            string_node.start_byte : string_node.end_byte
        ].decode('utf-8')
        try:
          docstring = ast.literal_eval(raw_docstring)
        except (ValueError, TypeError, SyntaxError):
          docstring = raw_docstring
    break
  return docstring


def extract_with_treesitter(file_path, decorator_filter=None):
  """Extracts function info using tree-sitter.

  Args:
      file_path: Path to the python file.
      decorator_filter: Optional decorator to filter by.

  Returns:
      A list of dictionaries containing function details.
  """
  # 1. Initialize Parser
  py_language = Language(tspython.language())
  parser = Parser(py_language)

  with open(file_path, 'rb') as f:
    source_code = f.read()

  # 2. Parse the source code
  tree = parser.parse(source_code)

  # 3. Define Query
  # We want to capture the function definition itself (@func)
  # AND its body (@body) so we know where to stop slicing.
  query_scm = """
    (function_definition
        name: (identifier) @name
        parameters: (parameters) @params
        body: (_) @body
    ) @func
    """
  query = Query(py_language, query_scm)

  results = []

  # 4. Iterate over matches
  cursor = QueryCursor(query)
  matches = cursor.matches(tree.root_node)

  # Iterate matches directly
  for _, captures in matches:
    # captures is a dict { name: [nodes] }
    if set(captures.keys()).issuperset({'func', 'body', 'name'}):
      name_node = captures['name'][0]
      func_node = captures['func'][0]
      body_node = captures['body'][0]
      name = source_code[name_node.start_byte : name_node.end_byte].decode()

      # Extract argument names
      arg_names = _extract_arg_names(source_code, captures)

      # Extract decorators
      decorators, jsonrpc_description, start_byte = (
          _extract_decorators_and_jsonrpc(source_code, func_node)
      )

      # Filter if needed
      if decorator_filter and not any(
          d.startswith(decorator_filter) for d in decorators
      ):
        continue

      # Extract prototype
      prototype_text, prototype_text_without_decorator = _extract_prototype(
          source_code, func_node, body_node, start_byte
      )

      # Extract docstring
      docstring = _extract_docstring(source_code, body_node)

      results.append({
          'name': name,
          'args': arg_names,
          'prototype': prototype_text,
          'prototype_without_decorator': prototype_text_without_decorator,
          'decorators': decorators,
          'jsonrpc_description': jsonrpc_description,
          'docstring': docstring,
      })

  return results


FIRST_PART = """# Copyright (c) 2026 Google LLC
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

# WARNING: This file is generated, DO NOT edit it directly.
import argparse
from typing import Annotated, Any, Dict, List, Literal
from gateway.forward import forward_to, mcp_server, mcp_tool
from shared.config import load_config
from shared.types import *

try:
  import gateway.patcher
  _ = gateway.patcher
except ImportError as e:
  print(
      f"[WARNING] Failed to load gateway.patcher: {e}. 'patch_assembly' tool"
      " will not be available."
  )

try:
  import gateway.query
  _ = gateway.query
except ImportError as e:
  print(
      f"[WARNING] Failed to load gateway.query: {e}. 'sql_query' tool will"
      " not be available."
  )
"""

LAST_PART = """
if __name__ == "__main__":
  config = load_config()
  parser = argparse.ArgumentParser()
  parser.add_argument(
      "--transport", default="sse", choices=["sse", "stdio", "http"]
  )
  parser.add_argument(
      "--host", type=str, help="Host to listen on (for SSE/HTTP transport)"
  )
  parser.add_argument(
      "--port", type=int, help="Port to listen on (for SSE/HTTP transport)"
  )
  args = parser.parse_args()

  if args.transport in ["sse", "http"]:
    host = (
        args.host
        if args.host is not None
        else config.get("proxy_host", "localhost")
    )
    port = (
        args.port if args.port is not None else config.get("proxy_port", 8000)
    )
    mcp_server.run(transport=args.transport, host=host, port=port)
  else:
    mcp_server.run(transport="stdio")
"""


def main():
  # 1. Parse Gateway Tools
  gateway_tools = set()
  for gateway_file in sorted(glob.glob('gateway/*.py')):
    if gateway_file.endswith(('proxy.py', '__init__.py')):
      continue
    print(f'Processing {gateway_file}...')
    gateway_items = extract_with_treesitter(
        gateway_file, decorator_filter='@mcp_tool'
    )
    gateway_tools.update(item['name'] for item in gateway_items)
  print(f'Found gateway tools: {gateway_tools}')

  # 2. Parse Backend Tools
  tools_dir = 'ida_mcp/tools'
  tool_files = glob.glob(os.path.join(tools_dir, '*.py'))
  tool_files.sort()
  results = []
  for tool_file in tool_files:
    if tool_file.endswith('__init__.py'):
      continue
    print(f'Processing {tool_file}...')
    # Extract @jsonrpc tools from backend
    results.extend(
        extract_with_treesitter(tool_file, decorator_filter='@jsonrpc')
    )
  # 3. Generate Proxy
  with open('gateway/proxy.py', 'w') as f:
    f.write(FIRST_PART)
    for item in results:
      # Skip if defined in gateway
      if item['name'] in gateway_tools:
        print(
            f"Skipping proxy generation for {item['name']} (defined in gateway)"
        )
        continue

      # Skip tools marked as internal or skip_proxy
      if any(
          d.startswith(('@internal', '@skip_proxy')) for d in item['decorators']
      ):
        print(
            f"Skipping proxy generation for {item['name']} (marked as internal)"
        )
        continue

      description_arg = ''
      if item['jsonrpc_description']:
        description_arg = item['jsonrpc_description']

      prototype_part1, prototype_part2 = item[
          'prototype_without_decorator'
      ].split('(', maxsplit=1)
      instance_str = (
          'database_id: Annotated[str, "The unique identifier for the target'
          ' IDA database. You can obtain this ID by calling'
          ' list_available_databases, reading the ida://databases resource, or'
          ' by opening a new database via idalib_headless_open."], '
      )

      prototype = prototype_part1 + '(' + instance_str + prototype_part2

      forward_call = (
          f"  return await forward_to(database_id, \"{item['name']}\","
          ' locals())'
      )

      func_body = forward_call
      if item['docstring']:
        ds = item['docstring']
        # Handle triple quotes in docstring
        ds = ds.replace('"""', '\\"\\"\\"')
        func_body = f'  """{ds}"""\n{forward_call}'

      if not prototype.strip().startswith('async '):
        prototype = prototype.replace('def ', 'async def ', 1)

      f.write(
          f'@mcp_tool{description_arg}\n'
          + prototype
          + '\n'
          + func_body
          + '\n\n'
      )

    f.write(LAST_PART)


if __name__ == '__main__':
  main()
