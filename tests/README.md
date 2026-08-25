# IDA MCP Test Infrastructure

This directory contains the test suite and supporting infrastructure for the IDA
Model Context Protocol (MCP) server.

## Overview

The test system is designed to verify the correctness of the IDA MCP tools by
comparing their output against "golden data" extracted directly from IDA Pro's
internal database using the native SDK.

## File Descriptions

-   **test_binary.cpp**: The source code for the test targets. It contains
    various C++ constructs (global variables, structures, complex functions, and
    control flow) specifically designed to test different aspects of IDA's
    analysis.
-   **test_binary**: The x86-64 executable compiled from `test_binary.cpp`.
-   **test_binary_arm64**: The ARM64 executable compiled from `test_binary.cpp`,
    typically cross-compiled for Android.
-   **Makefile**: The build script used to compile `test_binary` and
    `test_binary_arm64` from the source. It ensures consistent compilation flags
    (e.g., `-O0 -g`) for predictable analysis.
-   **dump_golden_data.py**: An IDA Python script that must be run within a
    native IDA Pro instance. It uses the IDA SDK to extract the "ground truth"
    (addresses, function names, types, cross-references, etc.) from the test
    binaries.
-   **golden_data.json**: The output of `dump_golden_data.py`. This file
    contains the ground truth database representation used for unit test
    assertions.
-   **test_tools.py**: The primary test suite. It orchestrates the testing
    process by:

    1.  Spawning the MCP gateway and backend.
    2.  Loading the test binaries into headless IDA instances.
    3.  Executing MCP tool calls.
    4.  Validating the tool responses against the ground truth in
        `golden_data.json`.

## Relationship and Workflow

1.  **Code**: Changes to `test_binary.cpp` define new scenarios to test.
2.  **Build**: `Makefile` produces the binary targets.
3.  **Extract**: `dump_golden_data.py` is executed in IDA to update
    `golden_data.json` if the ground truth changes.

    Run the dump_golden_data.py script with idat:

    ```bash
    idat -B -Stests/dump_golden_data.py tests/test_binary
    ```

4.  **Verify**: `test_tools.py` runs the MCP tools and asserts their correctness
    based on the golden data.
