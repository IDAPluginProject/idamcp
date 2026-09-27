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

"""Validated load options for headless idalib instances.

Only three IDA command-line switches are exposed, each from a structured
value, never from a raw argument string:

  processor     -> -p<name>     e.g. "metapc", "arm:ARMv7-M"
  loader        -> -T<prefix>   file type name prefix, e.g. "Binary file"
  base_address  -> -b<para>     load address; IDA takes it in 16-byte
                                paragraphs, so it must be 16-byte aligned

Anything else (notably -S, which runs a script, and -O plugin options) cannot
be expressed. The same validation runs in the gateway and in the headless
process. This module only uses the standard library.
"""

import dataclasses
import re

# The first character must be alphanumeric so a value can never start with
# "-" and be read as another switch.
_PROCESSOR_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:+-]{0,31}$")
_LOADER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.,()/+-]{0,63}$")
_MAX_BASE = (1 << 64) - 1
DATABASE_SUFFIXES = (".idb", ".i64")


class LoadOptionsError(ValueError):
  """Raised for an invalid or unsupported load option."""


@dataclasses.dataclass(frozen=True)
class LoadOptions:
  """Validated load options. Empty means "IDA defaults"."""

  processor: str | None = None
  loader: str | None = None
  base_address: int | None = None

  def is_empty(self) -> bool:
    return (
        self.processor is None
        and self.loader is None
        and self.base_address is None
    )

  def to_ida_args(self) -> str:
    """Returns the idalib `args` string, e.g. '-parm -T"Binary file" -b1000'."""
    parts = []
    if self.processor is not None:
      parts.append(f"-p{self.processor}")
    if self.loader is not None:
      parts.append(
          f'-T"{self.loader}"' if " " in self.loader else f"-T{self.loader}"
      )
    if self.base_address is not None:
      parts.append(f"-b{self.base_address >> 4:X}")
    return " ".join(parts)

  def to_cli(self) -> list[str]:
    """Returns argv options for `python -m ida_mcp.headless`."""
    argv = []
    if self.processor is not None:
      argv += ["--processor", self.processor]
    if self.loader is not None:
      argv += ["--loader", self.loader]
    if self.base_address is not None:
      argv += ["--base-address", hex(self.base_address)]
    return argv


def _blank_to_none(value: str | None) -> str | None:
  if value is None:
    return None
  value = value.strip()
  return value or None


def parse_load_options(
    processor: str | None = None,
    loader: str | None = None,
    base_address: str | int | None = None,
) -> LoadOptions:
  """Validates raw values and returns LoadOptions.

  Args:
    processor: IDA processor module name (`-p`), e.g. "metapc" or
      "arm:ARMv7-M".
    loader: file type name or prefix as IDA lists it (`-T`), e.g.
      "Binary file".
    base_address: load address as an int or a string accepted by `int(x, 0)`
      (e.g. "0x10000"); must be 16-byte aligned.

  Returns:
    The validated options.

  Raises:
    LoadOptionsError: if a value is malformed.
  """
  processor = _blank_to_none(processor)
  loader = _blank_to_none(loader)
  if processor is not None and not _PROCESSOR_RE.fullmatch(processor):
    raise LoadOptionsError(
        f"Invalid processor {processor!r}: expected 1-32 characters from"
        " A-Z a-z 0-9 _ . : + -, starting with a letter or digit"
    )
  # A space followed by "-" could start another switch if IDA ever split the
  # quoted -T value; no IDA file type name needs it.
  if loader is not None and (
      not _LOADER_RE.fullmatch(loader) or re.search(r"\s-", loader)
  ):
    raise LoadOptionsError(
        f"Invalid loader {loader!r}: expected 1-64 characters from"
        " A-Z a-z 0-9 space _ . , ( ) / + -, starting with a letter or digit,"
        ' and no " -"'
    )

  base = None
  if isinstance(base_address, str):
    base_address = _blank_to_none(base_address)
  if base_address is not None:
    if isinstance(base_address, bool):
      raise LoadOptionsError("Invalid base_address: expected an integer")
    try:
      base = (
          base_address
          if isinstance(base_address, int)
          else int(base_address, 0)
      )
    except ValueError as e:
      raise LoadOptionsError(
          f"Invalid base_address {base_address!r}: expected an integer such"
          " as 0x10000"
      ) from e
    if not 0 <= base <= _MAX_BASE:
      raise LoadOptionsError(f"base_address {base:#x} is out of range")
    if base % 16:
      raise LoadOptionsError(
          f"base_address {base:#x} must be 16-byte aligned (IDA's -b switch"
          " takes a paragraph number)"
      )
  return LoadOptions(processor=processor, loader=loader, base_address=base)


def check_applicable(path: str, options: LoadOptions) -> None:
  """Rejects load options for an existing IDA database, where they don't apply.

  Args:
    path: the path being opened.
    options: the validated options.

  Raises:
    LoadOptionsError: if options are set and path is a .idb/.i64 file.
  """
  if not options.is_empty() and path.lower().endswith(DATABASE_SUFFIXES):
    raise LoadOptionsError(
        "Load options only apply when loading a new binary, not when opening"
        f" an existing IDA database ({path})."
    )
