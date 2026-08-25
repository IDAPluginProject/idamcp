# Copyright (c) 2026 Google LLC
# Copyright (c) 2025 Duncan Ogilvie
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

"""Module for synchronizing with the IDA main thread."""

import asyncio
import enum
import functools
import logging
import sys
from typing import Any, Callable

import ida_kernwin
from ida_mcp.core import ida_thread
from ida_mcp.core.decorators import get_cancellation_token
import idaapi
import idc


class IDASyncError(Exception):
  pass


logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)


class IDASafety(enum.IntEnum):
  SAFE_NONE = ida_kernwin.MFF_FAST
  SAFE_READ = ida_kernwin.MFF_READ
  SAFE_WRITE = ida_kernwin.MFF_WRITE


def sync_wrapper(ff: Callable[[], Any], safety_mode: IDASafety) -> Any:
  """Call a function ff with a specific IDA safety_mode."""
  if safety_mode not in (IDASafety.SAFE_READ, IDASafety.SAFE_WRITE):
    error_str = "Invalid safety mode {} over function {}".format(
        safety_mode, ff.__name__
    )
    logger.error(error_str)
    raise IDASyncError(error_str)

  token = get_cancellation_token()
  if token is not None and token.is_cancelled:
    raise asyncio.CancelledError("Tool cancelled before execution")

  if idaapi.is_main_thread():
    old_batch = idc.batch(1)
    try:
      return ff()
    finally:
      idc.batch(old_batch)

  result_tuple: tuple[bool, Any] = (
      False,
      IDASyncError(f"execute_sync silently failed to execute {ff.__name__}"),
  )

  @functools.wraps(ff)
  def runned():
    # pylint: disable=broad-exception-caught
    nonlocal result_tuple
    if token is not None and token.is_cancelled:
      result_tuple = (
          False,
          asyncio.CancelledError("Tool cancelled before execution"),
      )
      return

    old_batch = idc.batch(1)
    old_profile = sys.getprofile()
    if token is not None:

      # We deliberately do not 'del' unused parameters to avoid emitting
      # extra DELETE_FAST opcodes in this performance-critical hook.
      def _ida_profile_func(unused_frame, unused_event, unused_arg) -> None:
        if token.is_cancelled:
          # Raising an exception automatically sets the profile function to
          # None.
          raise asyncio.CancelledError("Tool cancelled")

      sys.setprofile(_ida_profile_func)

    try:
      # Store a tuple: (Success_Boolean, Result_or_Exception)
      result_tuple = (True, ff())
    except (
        Exception,
        asyncio.CancelledError,
    ) as e:
      result_tuple = (False, e)
    finally:
      sys.setprofile(old_profile)
      idc.batch(old_batch)

  if getattr(idaapi, "is_headless", False):
    # Headless mode
    ida_thread.execute_sync(runned, safety_mode)
  else:
    idaapi.execute_sync(runned, safety_mode)

  success, res = result_tuple
  if not success:
    raise res
  return res


def _idasync(f: Callable[..., Any], mode: IDASafety) -> Callable[..., Any]:
  """Wraps a callable to execute synchronously inside the IDA main thread."""

  @functools.wraps(f)
  def wrapper(*args, **kwargs) -> Any:
    ff = functools.partial(f, *args, **kwargs)
    ff.__name__ = f.__name__  # type: ignore
    return sync_wrapper(ff, mode)

  # Python 3.14 compatibility: manually copy annotations and signature
  wrapper.__annotations__ = getattr(f, "__annotations__", {})
  if hasattr(f, "__signature__"):
    wrapper.__signature__ = f.__signature__  # type: ignore

  wrapper.is_ida_tool = True  # type: ignore
  return wrapper


def idawrite(f: Callable[..., Any]) -> Callable[..., Any]:
  """decorator for marking a function as modifying the IDB."""
  return _idasync(f, IDASafety.SAFE_WRITE)


def idaread(f: Callable[..., Any]) -> Callable[..., Any]:
  """decorator for marking a function as reading from the IDB."""
  return _idasync(f, IDASafety.SAFE_READ)
