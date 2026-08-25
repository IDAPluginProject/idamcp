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


"""Module for SQL-based queries on IDA Pro database using SQLite."""

import asyncio
import contextlib
import dataclasses
import functools
import logging
import pathlib
import queue
import signal
import sqlite3
import threading
import time
import traceback
from typing import Any, Iterable, List, Tuple, Union
import ida_auto
import ida_idp
import ida_kernwin
from ida_mcp.core.decorators import get_cancellation_token
from ida_mcp.core.decorators import jsonrpc
from ida_mcp.core.decorators import register_cancel_callback
from ida_mcp.core.synchronization import idaread
from ida_mcp.utils import helper
import ida_nalt
import ida_name
import ida_typeinf
import ida_xref
import idaapi
import idautils
import idc
from shared.config import load_config
from shared.rpc import ToolError

_image_min_ea = 0
_is_rebasing = False
_db_version_checked = False
_created_tables: set[str] = set()


@contextlib.contextmanager
def interruptible_sqlite(conn: sqlite3.Connection):
  """Registers a SQLite connection for cancellation interruption."""
  with register_cancel_callback(conn.interrupt):
    try:
      yield conn
    except (sqlite3.OperationalError, sqlite3.DatabaseError) as e:
      token = get_cancellation_token()
      if token is not None and token.is_cancelled:
        raise asyncio.CancelledError("SQL query was interrupted.") from e
      raise


# Global SQLite connections (Shared Memory or Persistent)
_db_local = threading.local()
_db_write_lock = threading.RLock()


def _is_tid(n: int) -> bool:
  """Check if a number is a TID."""
  return (n & 0xFFFFFFFF00000000) == 0xFF00000000000000


def _ro_authorizer(action, arg1, arg2, dbname, source):
  """Intercepts and denies any write operations for the RO connection."""
  del arg1, arg2, dbname, source  # Unused
  # Allowed operations for read-only query
  allowed = {
      sqlite3.SQLITE_SELECT,
      sqlite3.SQLITE_READ,
      sqlite3.SQLITE_FUNCTION,
      sqlite3.SQLITE_PRAGMA,
  }
  if hasattr(sqlite3, "SQLITE_RECURSIVE"):
    allowed.add(sqlite3.SQLITE_RECURSIVE)
  if action in allowed:
    return sqlite3.SQLITE_OK
  # Deny everything else (INSERT, UPDATE, DROP, etc.)
  return sqlite3.SQLITE_DENY


def _get_db_path_and_uri() -> Tuple[str, bool]:
  """Determines DB path and whether it's a URI."""
  config = load_config()
  idb_path = getattr(idaapi, "idb_path", None)
  if idb_path is None:
    with contextlib.suppress(Exception):
      import ida_loader

      idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
  if idb_path is not None:
    path = pathlib.Path(idb_path).with_suffix(".db")
    if (
        config.get("sqlite_persistent")
        or config.get("duckdb_persistent")
        or path.is_file()
    ):
      return str(path), False

  # Default to shared memory if not persistent
  return "file:memdb?mode=memory&cache=shared", True


def _to_signed_64(val: int) -> int:
  if val < -0x8000000000000000 or val > 0xFFFFFFFFFFFFFFFF:
    raise ValueError(f"Integer {val} exceeds 64-bit integer limit")
  return val if val < 0x8000000000000000 else val - 0x10000000000000000


def _create_connection(read_only: bool = False):
  """Creates a SQLite connection."""
  path, is_uri = _get_db_path_and_uri()
  if not is_uri and not pathlib.Path(path).exists():
    for suffix in ("-wal", "-shm"):
      aux_file = pathlib.Path(path + suffix)
      if aux_file.exists():
        with contextlib.suppress(OSError):
          aux_file.unlink()

  conn = sqlite3.connect(
      path, uri=is_uri, isolation_level=None, check_same_thread=False
  )

  # Performance pragmas
  conn.execute("PRAGMA cache_size = -65536")  # 64MB page cache
  if not is_uri:
    conn.execute("PRAGMA journal_mode = WAL")  # Non-blocking concurrent I/O
    conn.execute("PRAGMA synchronous = NORMAL")  # Fast, crash-safe sync in WAL
    conn.execute("PRAGMA mmap_size = 4294967296")  # 4GB memory-mapped I/O

  if read_only:
    conn.set_authorizer(_ro_authorizer)

  return conn


def _set_stored_min_ea(conn: sqlite3.Connection, min_ea: int) -> None:
  conn.execute(
      "CREATE TABLE IF NOT EXISTS _db_metadata (key TEXT PRIMARY KEY, value"
      " TEXT)"
  )
  conn.execute(
      "INSERT OR REPLACE INTO _db_metadata (key, value) VALUES"
      " ('image_min_ea', ?)",
      (hex(min_ea),),
  )


def _get_stored_min_ea(conn: sqlite3.Connection) -> int | None:
  with contextlib.suppress(sqlite3.OperationalError):
    cursor = conn.execute(
        "SELECT value FROM _db_metadata WHERE key = 'image_min_ea'"
    )
    row = cursor.fetchone()
    if row and row[0] is not None:
      return int(row[0], 0)
  return None


def _check_and_migrate_db(conn: sqlite3.Connection) -> None:
  """Checks user_version and image_min_ea; migrates (recreates) DB if outdated.

  Version 3.0 (represented as integer 3) anchors the table schema.
  If target_version is older than 3 or if the recorded image_min_ea has changed,
  all tables are dropped and re-created from scratch.

  Args:
    conn: SQLite connection to inspect and migrate.
  """
  with _db_write_lock:
    cursor = conn.execute("PRAGMA user_version")
    row = cursor.fetchone()
    current_version = row[0] if row else 0

    target_version = 3
    stored_min_ea = _get_stored_min_ea(conn)

    needs_migration = (
        current_version < target_version or stored_min_ea != _image_min_ea
    )

    if needs_migration:
      logging.info(
          "Database migration needed: version=%d (target=%d), stored_min_ea=%s"
          " (current=%s). Re-creating from scratch.",
          current_version,
          target_version,
          hex(stored_min_ea) if stored_min_ea is not None else "None",
          hex(_image_min_ea),
      )
      conn.execute("BEGIN TRANSACTION")
      try:
        entities = conn.execute(
            "SELECT type, name FROM sqlite_master WHERE type IN ('table',"
            " 'view') AND name NOT LIKE 'sqlite_%'"
        ).fetchall()

        for ent_type, name in entities:
          if ent_type == "view":
            conn.execute(f'DROP VIEW IF EXISTS "{name}"')
          elif ent_type == "table":
            conn.execute(f'DROP TABLE IF EXISTS "{name}"')

        conn.execute(f"PRAGMA user_version = {target_version}")
        _set_stored_min_ea(conn, _image_min_ea)
        conn.execute("COMMIT")
        _created_tables.clear()
        logging.info(
            "Database re-created, version set to %d, image_min_ea recorded as"
            " %s.",
            target_version,
            hex(_image_min_ea),
        )
      except Exception:
        conn.execute("ROLLBACK")
        logging.exception("Failed to migrate database")
        raise
    else:
      tables = conn.execute(
          "SELECT name FROM sqlite_master WHERE type='table'"
      ).fetchall()
      _created_tables.update(
          t[0].lower() for t in tables if t[0].lower() != "_db_metadata"
      )


def _get_rw_conn():
  """Returns a read-write SQLite connection."""
  global _db_version_checked
  if not hasattr(_db_local, "rw_conn"):
    _db_local.rw_conn = _create_connection(read_only=False)
  if not _db_version_checked:
    _check_and_migrate_db(_db_local.rw_conn)
    _db_version_checked = True
  return _db_local.rw_conn


def _get_ro_conn():
  """Returns a read-only SQLite connection enforced by an authorizer."""
  if not _db_version_checked:
    _get_rw_conn()
  if not hasattr(_db_local, "ro_conn"):
    _db_local.ro_conn = _create_connection(read_only=True)
  return _db_local.ro_conn


# Xref type mapping
XREF_TYPE_MAP = {
    idaapi.fl_CF: "call",
    idaapi.fl_CN: "call",
    idaapi.fl_JF: "jmp",
    idaapi.fl_JN: "jmp",
    idaapi.fl_F: "flow",
    idaapi.dr_R: "read",
    idaapi.dr_W: "write",
    idaapi.dr_O: "offset",
    idaapi.dr_T: "text",
    idaapi.dr_I: "informational",
    idaapi.dr_S: "enum_member",
}


def _get_xref_type_name(xref_type):
  """Converts IDA xref type to string name."""
  return XREF_TYPE_MAP.get(xref_type, "other")


def _recreate_and_insert(
    table_name: str,
    schema: str,
    data: Iterable[tuple[Any, ...]],
    column_count: int,
    batch_size: int = 1000,
):
  """Recreates a table and inserts data using the RW connection."""
  with _db_write_lock:
    conn = _get_rw_conn()
    tmp_table = f"{table_name}_tmp"

    with interruptible_sqlite(conn):
      conn.execute("BEGIN TRANSACTION")
      try:
        conn.execute(f"DROP TABLE IF EXISTS {tmp_table}")
        conn.execute(f"CREATE TABLE {tmp_table} ({schema})")

        batch = []
        placeholders = ", ".join(["?"] * column_count)
        sql_insert = f"INSERT INTO {tmp_table} VALUES ({placeholders})"

        for item in data:
          batch.append(item)
          if len(batch) >= batch_size:
            conn.executemany(sql_insert, batch)
            batch.clear()

        if batch:
          conn.executemany(sql_insert, batch)

        conn.execute(f"DROP TABLE IF EXISTS {table_name}")
        conn.execute(f"ALTER TABLE {tmp_table} RENAME TO {table_name}")
        conn.execute("COMMIT")
        _created_tables.add(table_name.lower())
      except (Exception, asyncio.CancelledError):
        conn.execute("ROLLBACK")
        raise

      finally:
        # We check conn.in_transaction in case the profile function raises
        # asyncio.CancelledError right before conn.execute, preventing
        # the ROLLBACK action from completing.

        if conn.in_transaction:
          try:
            conn.execute("ROLLBACK")
          except sqlite3.Error:
            pass


def _table_exists(table_name: str) -> bool:
  """Checks if a table exists in the database."""
  if not _db_version_checked:
    _get_rw_conn()
  return table_name.lower() in _created_tables


@dataclasses.dataclass
class FuncInfo:
  start_ea: int
  end_ea: int
  name: str
  demangled_name: str | None
  prototype: str | None
  size: int


@idaread
def _get_func_info(func_ea: int) -> FuncInfo | None:
  """Retrieves function metadata.

  Validates that `func_ea` is the starting address (entry point) of a function.
  If valid, extracts its boundaries, name, demangled name, type prototype, and
  size.

  Args:
    func_ea: Absolute effective address of the function entry point.

  Returns:
    A `FuncInfo` object containing function metadata if `func_ea` is the start
    address of a function, or `None` if it is not a function entry point.
  """
  bounds = helper.get_func_bounds(func_ea)
  if bounds is None or bounds.start_ea != func_ea:
    return None

  func_size = bounds.end_ea - bounds.start_ea

  func_name = idaapi.get_func_name(bounds.start_ea)
  if func_name is not None:
    demangled = ida_name.demangle_name(func_name, ida_name.MNG_NODEFINIT)
  else:
    func_name = "<unknown>"
    demangled = None

  tif = ida_typeinf.tinfo_t()
  if ida_nalt.get_tinfo(tif, bounds.start_ea):
    proto = tif.dstr()
  else:
    proto = idc.get_type(bounds.start_ea)

  return FuncInfo(
      start_ea=_to_signed_64(bounds.start_ea),
      end_ea=_to_signed_64(bounds.end_ea),
      name=func_name,
      demangled_name=demangled if demangled else None,
      prototype=proto if proto else None,
      size=func_size,
  )


def _time_populator(func):
  """Decorator to measure and print execution time of populator functions."""

  @functools.wraps(func)
  def wrapper(*args, **kwargs):
    start = time.perf_counter()
    try:
      return func(*args, **kwargs)
    finally:
      duration = time.perf_counter() - start
      print(f"[>] {func.__name__} took {duration:.4f}s", flush=True)

  return wrapper


@_time_populator
@idaread
def populate_functions():
  """Populates the functions table."""

  def _gen():
    for address in helper.iter_function_addresses():
      info: FuncInfo | None = _get_func_info(address)
      if info is not None:
        yield (
            info.start_ea,
            info.end_ea,
            info.name,
            info.demangled_name,
            info.prototype,
            info.size,
        )

  _recreate_and_insert(
      "functions",
      "start_ea INTEGER, end_ea INTEGER, name TEXT, demangled_name TEXT,"
      " prototype TEXT, size INTEGER",
      _gen(),
      column_count=6,
  )
  with _db_write_lock:
    conn = _get_rw_conn()
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_functions_start ON functions (start_ea)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_functions_end ON functions (end_ea)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_functions_name ON functions (name,"
        " start_ea, size)"
    )


@_time_populator
@idaread
def populate_strings():
  """Populates the strings table."""
  global _strings_dirty

  def _gen():
    for item in idautils.Strings():
      if item is None:
        continue
      yield (
          _to_signed_64(item.ea),
          item.length,
          str(item),
      )

  _recreate_and_insert(
      "strings",
      "address INTEGER, length INTEGER, string TEXT",
      _gen(),
      column_count=3,
  )
  with _db_write_lock:
    conn = _get_rw_conn()
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_strings_addr ON strings (address,"
        " length)"
    )
  _strings_dirty = False


@_time_populator
@idaread
def populate_names():
  """Populates the names table."""

  def _gen():
    for addr, name in idautils.Names():
      if name:
        yield (_to_signed_64(addr), name)

  _recreate_and_insert(
      "names", "address INTEGER, name TEXT", _gen(), column_count=2
  )
  with _db_write_lock:
    conn = _get_rw_conn()
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_names_address ON names (address)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_names_name ON names (name, address)"
    )


@_time_populator
@idaread
def populate_imports():
  """Populates the imports table."""

  def _gen():
    nimps = ida_nalt.get_import_module_qty()
    for i in range(nimps):
      module_name = ida_nalt.get_import_module_name(i) or "<unnamed>"
      module_imports = []

      # Callback closure.
      # pylint: disable=cell-var-from-loop
      def imp_cb(ea, name, ordinal):
        symbol_name = name if name else f"#{ordinal}"
        module_imports.append((
            _to_signed_64(ea),
            symbol_name,
            module_name,
        ))
        return True

      # pylint: disable=cell-var-from-loop
      ida_nalt.enum_import_names(i, imp_cb)
      yield from module_imports

  _recreate_and_insert(
      "imports",
      "address INTEGER, name TEXT, module TEXT",
      _gen(),
      column_count=3,
  )
  with _db_write_lock:
    conn = _get_rw_conn()
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_imports_address ON imports (address)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_imports_name ON imports (name, module,"
        " address)"
    )


def _get_segments_info_inner():
  """Retrieves inner segments information."""
  data = []
  for seg in helper.get_segments():
    data.append((
        seg.name,
        seg.sclass,
        _to_signed_64(seg.start_ea),
        _to_signed_64(seg.end_ea),
        seg.end_ea - seg.start_ea,
        helper.ida_segment_perm2str(seg.perm),
    ))
  return data


@_time_populator
@idaread
def populate_segments():
  """Populates the segments table."""
  data = _get_segments_info_inner()
  _recreate_and_insert(
      "segments",
      "name TEXT, class TEXT, start_ea INTEGER, end_ea INTEGER, size"
      " INTEGER, permissions TEXT",
      data,
      column_count=6,
  )
  with _db_write_lock:
    conn = _get_rw_conn()
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_segments_start ON segments (start_ea,"
        " end_ea)"
    )


@dataclasses.dataclass
class LocalTypeInfo:
  ordinal: int
  name: str
  declaration: str | None


def _get_local_type_info(ordinal: int) -> LocalTypeInfo | None:
  """Retrieves local type info."""
  idati = ida_typeinf.get_idati()
  tif = ida_typeinf.tinfo_t()
  if not tif.get_numbered_type(idati, ordinal):
    return None
  type_name = tif.get_type_name()
  if not type_name:
    type_name = f"anonymous_type_{ordinal}"

  c_decl_flags = (
      ida_typeinf.PRTYPE_MULTI
      | ida_typeinf.PRTYPE_TYPE
      | ida_typeinf.PRTYPE_SEMI
      | ida_typeinf.PRTYPE_DEF
      | ida_typeinf.PRTYPE_METHODS
      | (ida_typeinf.PRTYPE_OFFSETS if idaapi.is_idaq() else 0)
  )
  # Accessing protected member _print to generate C declaration.
  # pylint: disable=protected-access
  # The method declaration says the return value is `boolean` , while in fact
  # it is a string.
  c_decl_output = tif._print(str(type_name), c_decl_flags)
  return LocalTypeInfo(
      ordinal=ordinal,
      name=type_name,
      declaration=c_decl_output if c_decl_output else None,
  )


@_time_populator
@idaread
def populate_local_types():
  """Populates the local_types table."""

  def _gen():
    idati = ida_typeinf.get_idati()
    type_count = helper.get_ordinal_limit(idati)
    for ordinal in range(1, type_count):
      try:
        info = _get_local_type_info(ordinal)
        if info:
          yield (info.ordinal, info.name, info.declaration)
      except Exception:  # pylint: disable=broad-exception-caught
        continue

  _recreate_and_insert(
      "local_types",
      "ordinal INTEGER, name TEXT, declaration TEXT",
      _gen(),
      column_count=3,
  )
  with _db_write_lock:
    conn = _get_rw_conn()
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_local_types_name ON local_types (name,"
        " ordinal)"
    )


@_time_populator
@idaread
def populate_xrefs() -> None:
  """Populates the xrefs table."""

  def _gen():
    xb = ida_xref.xrefblk_t()
    flags = 0
    for attr_name in ("XREF_FAR", "XREF_NOFLOW", "XREF_EA"):
      flags |= getattr(ida_xref, attr_name, 0)

    current_start = 0
    current_end = 0
    from_func_ea = None

    for head in idautils.Heads():
      if not (current_start <= head < current_end):
        pfn = helper.get_func_bounds(head)
        if pfn:
          current_start = pfn.start_ea
          current_end = pfn.end_ea
          from_func_ea = _to_signed_64(current_start)
        else:
          current_start = head
          next_pfn = helper.get_next_func_bounds(head)
          current_end = (
              next_pfn.start_ea if next_pfn else idaapi.inf_get_max_ea()
          )
          from_func_ea = None

      if xb.first_from(head, flags):
        # In the newer version of IDA Pro, XREF_EA excludes the tid, but the
        # older versions do not have the XREF_EA flag.
        if not _is_tid(xb.to):
          yield (
              _to_signed_64(head),
              _to_signed_64(xb.to),
              _get_xref_type_name(xb.type),
              from_func_ea,
          )
        while xb.next_from():
          if not _is_tid(xb.to):
            yield (
                _to_signed_64(head),
                _to_signed_64(xb.to),
                _get_xref_type_name(xb.type),
                from_func_ea,
            )

  _recreate_and_insert(
      "xrefs",
      (
          "from_ea INTEGER, to_ea INTEGER, type TEXT, from_function_ea INTEGER,"
          " UNIQUE(from_ea, to_ea, type)"
      ),
      _gen(),
      column_count=4,
  )
  with _db_write_lock:
    conn = _get_rw_conn()
    conn.execute("CREATE INDEX IF NOT EXISTS idx_xrefs_from ON xrefs (from_ea)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_xrefs_to ON xrefs (to_ea)")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_xrefs_from_func ON xrefs"
        " (from_function_ea)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_xrefs_from_func_cov ON xrefs"
        " (from_function_ea, to_ea, type)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_xrefs_to_cov ON xrefs"
        " (to_ea, from_ea, type, from_function_ea)"
    )


POPULATORS = {
    "functions": populate_functions,
    "strings": populate_strings,
    "names": populate_names,
    "imports": populate_imports,
    "segments": populate_segments,
    "local_types": populate_local_types,
    "xrefs": populate_xrefs,
}

_strings_dirty = False
_skip_string_updates = False


@jsonrpc
def sql_query(
    queries: list[dict[str, Any]],
) -> list[Union[List[dict[str, Any]], str]]:
  """Executes pre-rewritten read-only SQL queries against IDA Pro using SQLite.

  Args:
    queries: A list of dicts, where each dict has: - 'sql': The rewritten SQL
      query string. - 'tables': A list of table names required by this query.

  Returns:
    A list of query results (one per input query in the batch).
  """
  if not _db_initialized:
    init_tables()
  else:
    _db_update_queue.join()

  if _is_rebasing:
    raise ToolError(
        "Database is currently undergoing rebase and auto-analysis. Please wait"
        " for reanalysis to complete before querying."
    )

  global _skip_string_updates
  results = []
  for item in queries:
    q = item.get("sql", "").strip()
    if not q:
      continue
    tables = item.get("tables", [])
    try:
      # Ensure required tables are populated
      for table_name in map(str.lower, tables):
        if table_name in POPULATORS:
          if not _table_exists(table_name):
            POPULATORS[table_name]()
          elif (
              not _skip_string_updates
              and table_name == "strings"
              and _strings_dirty
          ):
            if getattr(idaapi, "is_headless", False):
              POPULATORS[table_name]()
            else:
              # pylint: disable=used-prior-global-declaration
              @idaread
              def ask_buttons() -> int:
                return ida_kernwin.ask_buttons(
                    "Update",
                    "No",
                    "Don't Ask Again",
                    1,
                    "IDB patches detected. Your 'strings' table may be out of"
                    " sync.\n\nWould you like to re-index it now?",
                )

              btn_choice = ask_buttons()
              if btn_choice == 1:
                POPULATORS[table_name]()
              elif btn_choice == -1:
                _skip_string_updates = True

      conn = _get_ro_conn()
      with interruptible_sqlite(conn):
        cursor = conn.execute(q)
        if not cursor.description:
          results.append("Query executed successfully.")
          continue

        rows = cursor.fetchall()
        columns = [desc[0] for desc in cursor.description]

      res = []
      for row in rows:
        row_dict = dict(zip(columns, row))
        for k, v in row_dict.items():
          if isinstance(v, int):
            row_dict[k] = f"{v & 0xFFFFFFFFFFFFFFFF:#x}"
        res.append(row_dict)
      results.append(res)
    except Exception as e:
      results.append(f"Error executing SQL: {str(e)}\n{traceback.format_exc()}")

  return results


_db_update_queue: queue.Queue[tuple[Any, ...]] = queue.Queue()


def _populate_tables() -> None:
  print("[>] Populating all tables, please wait...", flush=True)
  for table_name, populator in POPULATORS.items():
    if not _table_exists(table_name):
      try:
        populator()
      except Exception as e:  # pylint: disable=broad-exception-caught
        logging.exception("Failed to repopulate table %s: %s", table_name, e)
  print("[+] All tables are ready...", flush=True)


def _db_worker():
  """Background worker to update SQLite from IDA event queue."""
  dirty_tables: dict[str, Any] = {}
  while True:
    event = _db_update_queue.get()
    try:
      action = event[0]
      if action == "quit":
        break

      if action == "rebase_invalidation":
        with _db_write_lock:
          conn = _get_rw_conn()
          for table in list(_created_tables):
            conn.execute(f'DROP TABLE IF EXISTS "{table}"')
          _created_tables.clear()
        continue

      if action == "rebase_completed":
        with _db_write_lock:
          conn = _get_rw_conn()
          _set_stored_min_ea(conn, _image_min_ea)
        continue

      if action == "repopulate_tables":
        _populate_tables()
        logging.info(
            "Table repopulation complete after rebase. Database is ready."
        )
        continue

      with _db_write_lock:
        cursor = _get_rw_conn().cursor()
        try:
          match action:
            case "renamed":
              func_info: FuncInfo | None
              ea, new_name, func_info = event[1:4]
              signed_ea = _to_signed_64(ea)
              if _table_exists("names"):
                cursor.execute(
                    "DELETE FROM names WHERE address = ?", (signed_ea,)
                )
                if new_name:
                  cursor.execute(
                      "INSERT INTO names (address, name) VALUES (?, ?)",
                      (signed_ea, new_name),
                  )

              if _table_exists("functions"):
                cursor.execute(
                    "UPDATE functions SET name = ? WHERE start_ea = ?",
                    (new_name, signed_ea),
                )
                if func_info is not None:
                  cursor.execute(
                      "UPDATE functions SET demangled_name = ?, prototype = ?"
                      " WHERE start_ea = ?",
                      (
                          func_info.demangled_name,
                          func_info.prototype,
                          signed_ea,
                      ),
                  )

            case "func_added" | "func_updated":
              func_info: FuncInfo | None
              ea, func_info = event[1:3]
              signed_ea = _to_signed_64(ea)
              if _table_exists("functions"):
                cursor.execute(
                    "DELETE FROM functions WHERE start_ea = ?", (signed_ea,)
                )
                if func_info is not None:
                  cursor.execute(
                      "INSERT INTO functions VALUES (?, ?, ?, ?, ?, ?)",
                      (
                          func_info.start_ea,
                          func_info.end_ea,
                          func_info.name,
                          func_info.demangled_name,
                          func_info.prototype,
                          func_info.size,
                      ),
                  )

            case "func_deleted":
              ea = event[1]
              if _table_exists("functions"):
                cursor.execute(
                    "DELETE FROM functions WHERE start_ea = ?",
                    (_to_signed_64(ea),),
                )

            case "local_type_changed":
              info: LocalTypeInfo | None
              ordinal, info = event[1:3]
              if _table_exists("local_types"):
                cursor.execute(
                    "DELETE FROM local_types WHERE ordinal = ?", (ordinal,)
                )
                if info is not None:
                  cursor.execute(
                      "INSERT INTO local_types VALUES (?, ?, ?)",
                      (info.ordinal, info.name, info.declaration),
                  )

            case "segment_changed":
              dirty_tables["segments"] = event[1]

            case "cref_added" | "dref_added":
              from_ea, to_ea, type_val, from_function_ea = event[1:5]
              if _table_exists("xrefs"):
                cursor.execute(
                    "INSERT OR IGNORE INTO xrefs (from_ea,"
                    " to_ea, type, from_function_ea)"
                    " VALUES (?, ?, ?, ?)",
                    (
                        _to_signed_64(from_ea),
                        _to_signed_64(to_ea),
                        _get_xref_type_name(type_val),
                        (
                            _to_signed_64(from_function_ea)
                            if from_function_ea is not None
                            else None
                        ),
                    ),
                )

            case "cref_deleted":
              from_ea, to_ea = event[1:3]
              if _table_exists("xrefs"):
                cursor.execute(
                    "DELETE FROM xrefs WHERE from_ea = ? AND"
                    " to_ea = ? AND type IN ('call', 'jmp', 'other')",
                    (
                        _to_signed_64(from_ea),
                        _to_signed_64(to_ea),
                    ),
                )

            case "dref_deleted":
              from_ea, to_ea = event[1:3]
              if _table_exists("xrefs"):
                cursor.execute(
                    """
                    DELETE FROM xrefs
                    WHERE from_ea = ? AND to_ea = ?
                      AND type IN ('read', 'write', 'offset', 'informational',
                        'text', 'enum_member', 'other')
                    """,
                    (
                        _to_signed_64(from_ea),
                        _to_signed_64(to_ea),
                    ),
                )
        except Exception as e:  # pylint: disable=broad-exception-caught
          logging.exception("DB update error for event %s: %s", action, e)
        finally:
          cursor.close()

      if _db_update_queue.empty() and dirty_tables:
        if "segments" in dirty_tables and _table_exists("segments"):
          _recreate_and_insert(
              "segments",
              "name TEXT, class TEXT, start_ea INTEGER, end_ea INTEGER,"
              " size INTEGER, permissions TEXT",
              dirty_tables["segments"],
              column_count=6,
          )
        dirty_tables.clear()
    except Exception as e:  # pylint: disable=broad-exception-caught
      logging.exception("DB worker error: %s", e)
    finally:
      _db_update_queue.task_done()


def skip_if_rebasing(func=None, *, default_return=None):
  """Decorator to skip hook callbacks when the database is rebasing."""

  def decorator(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
      if _is_rebasing:
        return default_return
      return f(*args, **kwargs)

    return wrapper

  if func is not None:
    return decorator(func)
  return decorator


def _trigger_rebase_invalidation() -> None:
  """Invalidates database tables and flushes pending queue upon rebase/move."""
  global _is_rebasing
  _is_rebasing = True

  while not _db_update_queue.empty():
    try:
      _db_update_queue.get_nowait()
      _db_update_queue.task_done()
    except queue.Empty:
      break

  _db_update_queue.put(("rebase_invalidation",))


def _complete_rebase_if_auto_ok() -> bool:
  """Completes rebase process if auto-analysis is finished."""
  global _is_rebasing, _image_min_ea
  if _is_rebasing and (not ida_auto.is_auto_enabled() or ida_auto.auto_is_ok()):
    _image_min_ea = idaapi.inf_get_min_ea()
    _is_rebasing = False
    config = load_config()
    if config.get("populate_tables_on_startup"):
      _db_update_queue.put(("repopulate_tables",))
    _db_update_queue.put(("rebase_completed",))
    return True
  return False


class DBUpdateHooks(ida_idp.IDB_Hooks):
  """IDA IDB hooks to track changes."""

  # pylint: disable=invalid-name, redefined-builtin

  @skip_if_rebasing
  def renamed(
      self,
      ea: "idaapi.ea_t",
      new_name: str,
      local_name: bool = False,
      old_name: str = "",
      *args: Any,
  ) -> None:
    del local_name, old_name, args
    func_info = _get_func_info(ea)
    _db_update_queue.put((
        "renamed",
        ea,
        new_name,
        func_info,
    ))

  @skip_if_rebasing
  def local_types_changed(
      self, ltc=None, ordinal: int = 0, name: str = "", *args: Any
  ) -> None:
    del ltc, name, args
    info = _get_local_type_info(ordinal)
    _db_update_queue.put(("local_type_changed", ordinal, info))

  @skip_if_rebasing
  def local_type_renamed(
      self, ordinal: int = 0, oldname: str = "", newname: str = "", *args: Any
  ) -> None:
    del oldname, newname, args
    info = _get_local_type_info(ordinal)
    _db_update_queue.put(("local_type_changed", ordinal, info))

  @skip_if_rebasing
  def func_added(self, pfn: idaapi.func_t, *args: Any) -> None:
    del args
    info = _get_func_info(pfn.start_ea)
    _db_update_queue.put(("func_added", pfn.start_ea, info))

  @skip_if_rebasing
  def func_deleted(self, func_ea: "idaapi.ea_t", *args: Any) -> None:
    del args
    _db_update_queue.put(("func_deleted", func_ea))

  @skip_if_rebasing
  def set_func_start(
      self, pfn: idaapi.func_t, new_start: "idaapi.ea_t" = 0, *args: Any
  ) -> None:
    del new_start, args
    info = _get_func_info(pfn.start_ea)
    _db_update_queue.put(("func_updated", pfn.start_ea, info))

  @skip_if_rebasing
  def set_func_end(
      self, pfn: idaapi.func_t, new_end: "idaapi.ea_t" = 0, *args: Any
  ) -> None:
    del new_end, args
    info = _get_func_info(pfn.start_ea)
    _db_update_queue.put(("func_updated", pfn.start_ea, info))

  @skip_if_rebasing
  def func_updated(self, pfn: idaapi.func_t, *args: Any) -> None:
    del args
    info = _get_func_info(pfn.start_ea)
    _db_update_queue.put(("func_updated", pfn.start_ea, info))

  @skip_if_rebasing
  def segm_added(self, s: idaapi.segment_t, *args: Any) -> None:
    del s, args
    _db_update_queue.put(("segment_changed", _get_segments_info_inner()))

  @skip_if_rebasing
  def segm_deleted(
      self,
      start_ea: "idaapi.ea_t" = 0,
      end_ea: "idaapi.ea_t" = 0,
      flags: int = 0,
      *args: Any,
  ) -> None:
    del start_ea, end_ea, flags, args
    _db_update_queue.put(("segment_changed", _get_segments_info_inner()))

  @skip_if_rebasing
  def segm_name_changed(
      self, s: idaapi.segment_t, name: str = "", *args: Any
  ) -> None:
    del s, name, args
    _db_update_queue.put(("segment_changed", _get_segments_info_inner()))

  @skip_if_rebasing
  def segm_moved(
      self,
      from_ea: "idaapi.ea_t" = 0,
      to: "idaapi.ea_t" = 0,
      size: int = 0,
      changed_netmap: bool = False,
      *args: Any,
  ) -> None:
    del from_ea, to, size, changed_netmap, args
    _trigger_rebase_invalidation()

  @skip_if_rebasing
  def segm_class_changed(
      self, s: idaapi.segment_t, sclass: str = "", *args: Any
  ) -> None:
    del s, sclass, args
    _db_update_queue.put(("segment_changed", _get_segments_info_inner()))

  @skip_if_rebasing
  def byte_patched(
      self, ea: "idaapi.ea_t" = 0, old_value: int = 0, *args: Any
  ) -> None:
    del ea, old_value, args
    global _strings_dirty
    _strings_dirty = True

  def allsegs_moved(self, info=None, *args: Any) -> None:
    del info, args
    _complete_rebase_if_auto_ok()

  # pylint: enable=invalid-name, redefined-builtin


class DBUpdateIDPHooks(ida_idp.IDP_Hooks):
  """IDA IDP hooks to track changes."""

  # pylint: disable=invalid-name, redefined-builtin

  @skip_if_rebasing(default_return=0)
  def ev_add_cref(
      self, _from: int = 0, to: int = 0, xref_type: int = 0, *args: Any
  ) -> int:
    del args
    bounds = helper.get_func_bounds(_from)
    from_function_ea = bounds.start_ea if bounds else None
    _db_update_queue.put(("cref_added", _from, to, xref_type, from_function_ea))
    return 0

  @skip_if_rebasing(default_return=0)
  def ev_add_dref(
      self, _from: int = 0, to: int = 0, xref_type: int = 0, *args: Any
  ) -> int:
    del args
    if not _is_tid(to):
      bounds = helper.get_func_bounds(_from)
      from_function_ea = bounds.start_ea if bounds else None
      _db_update_queue.put(
          ("dref_added", _from, to, xref_type, from_function_ea)
      )
    return 0

  @skip_if_rebasing(default_return=0)
  def ev_del_cref(
      self, _from: int = 0, to: int = 0, expand: bool = False, *args: Any
  ) -> int:
    del expand, args
    _db_update_queue.put(("cref_deleted", _from, to))
    return 0

  @skip_if_rebasing(default_return=0)
  def ev_del_dref(self, _from: int = 0, to: int = 0, *args: Any) -> int:
    del args
    # Ignore TID references, we should not use helper.is_address_valid here
    # because the image base may have changed.
    if not _is_tid(to):
      _db_update_queue.put(("dref_deleted", _from, to))
    return 0

  def ev_auto_queue_empty(self, type: "atype_t" = None, *args: Any) -> int:
    """One analysis queue is empty."""
    del type, args
    _complete_rebase_if_auto_ok()
    return 0

  # pylint: enable=invalid-name, redefined-builtin


_db_initialized = False
_db_hooks = None
_db_idp_hooks = None
_worker_thread = None
_handlers = {}


def _signal_handler(sig, frame):
  """Signals the background worker to quit."""
  _db_update_queue.put(("quit",))
  if sig in _handlers and _handlers[sig]:
    _handlers[sig](sig, frame)


@idaread
def init_tables() -> None:
  """Initializes the background worker and IDB hooks."""
  global _db_initialized, _db_hooks, _db_idp_hooks, _worker_thread
  global _image_min_ea
  if _db_initialized:
    return
  _image_min_ea = idaapi.inf_get_min_ea()
  _worker_thread = threading.Thread(target=_db_worker, daemon=True)
  _worker_thread.start()

  signals_to_handle = [signal.SIGINT]
  if hasattr(signal, "SIGTERM"):
    signals_to_handle.append(signal.SIGTERM)
  # SIGBREAK is not always available on all platforms (e.g. Linux).
  if hasattr(signal, "SIGBREAK"):
    signals_to_handle.append(signal.SIGBREAK)  # type: ignore

  for sig in signals_to_handle:
    try:
      _handlers[sig] = signal.signal(sig, _signal_handler)
    except Exception as e:  # pylint: disable=broad-exception-caught
      logging.exception("Could not register handler for signal %s: %s", sig, e)
  _db_hooks = DBUpdateHooks()
  _db_hooks.hook()
  _db_idp_hooks = DBUpdateIDPHooks()
  _db_idp_hooks.hook()
  _db_initialized = True

  config = load_config()
  if config.get("populate_tables_on_startup"):
    _populate_tables()
