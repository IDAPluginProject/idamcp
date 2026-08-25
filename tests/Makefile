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


PYTHON ?= python3

NDK_DIR = $(HOME)/android-ndk-r25b
ANDROID_CLANGXX ?= $(NDK_DIR)/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang++
MAKEFILE_DIR := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
CXXFLAGS = -O0 -g -gdwarf-4 -ggdb3 -ffile-prefix-map=$(MAKEFILE_DIR)=. \
		-ffile-prefix-map=$(NDK_DIR)=/ndk

.PHONY: all test_binary test_binary_arm64

# Default target
all: test_binary test_binary_arm64

# Compile test binary (x86-64)
test_binary: test_binary.cpp
	clang++ $(CXXFLAGS) test_binary.cpp -o test_binary
	chmod a-x test_binary

# Compile test binary (ARM64 - requires Android NDK clang++)
test_binary_arm64: test_binary.cpp
	@if [ -f $(ANDROID_CLANGXX) ]; then \
		$(ANDROID_CLANGXX) $(CXXFLAGS) test_binary.cpp -o test_binary_arm64 && \
		chmod a-x test_binary_arm64; \
	else \
		echo "ARM64 clang++ not found at $(ANDROID_CLANGXX)." >&2; \
		exit 1; \
	fi

# Clean up bytecode and caches
clean:
	rm -rf test_binary test_binary_arm64
