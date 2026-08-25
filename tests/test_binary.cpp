// Copyright (c) 2026 Google LLC
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <iostream>

// Global variables for testing (.data)

int global_int = 42;
char global_char = 'X';
short global_short = 1234;
double global_double = 3.14159;
const char* global_string = "Hello, MCP testing world!";
const char* global_string2 = "Hello, MCP testing world!";

// Uninitialized global variables (.bss)
int bss_int;
char bss_buffer[256];
double bss_double;

struct TestStruct {
  int a;
  char b;
  long c;
};

struct ComplexStruct {
  TestStruct t;
  int* ptr;
  char name[32];
};

TestStruct global_struct = {1, 'A', 100000L};
ComplexStruct complex_struct = {{2, 'B', 200000L}, &global_int, "Complex"};

__attribute__((noreturn)) void noreturn_function(int t) {
  if (t == 0) {
    exit(-1);
  }
  abort();
}

// A function to test call graphs, callers, callees
void callee_func() { std::cout << "Inside callee_func" << std::endl; }

void another_callee() { std::cout << "Inside another_callee" << std::endl; }

int caller_func(int arg) {
  if (arg > 0) {
    callee_func();
  } else {
    another_callee();
  }
  return arg * 2;
}

// Function with multiple local variables
int compute_locals(int a, int b) {
  int x = a + b;
  int y = a - b;
  int z = a * b;
  int w = 0;
  if (b != 0) {
    w = a / b;
  }

  char buffer[64];
  snprintf(buffer, sizeof(buffer), "x=%d, y=%d, z=%d, w=%d", x, y, z, w);
  std::cout << buffer << std::endl;

  return x + y + z + w;
}

// Function with a large switch statement
void handle_switch(int val) {
  std::cout << "Switching on: " << val << " - ";
  switch (val) {
    case 0:
      std::cout << "Zero" << std::endl;
      break;
    case 1:
      std::cout << "One" << std::endl;
      break;
    case 2:
      std::cout << "Two" << std::endl;
      break;
    case 3:
      std::cout << "Three" << std::endl;
      break;
    case 4:
      std::cout << "Four" << std::endl;
      break;
    case 5:
      std::cout << "Five" << std::endl;
      break;
    case 10:
      std::cout << "Ten" << std::endl;
      break;
    case 42:
      std::cout << "The Answer" << std::endl;
      break;
    case 100:
      std::cout << "One Hundred" << std::endl;
      break;
    default:
      std::cout << "Other" << std::endl;
      break;
  }
}

// Function with loops
int process_loop(int limit) {
  int sum = 0;

  // For loop
  for (int i = 0; i < limit; ++i) {
    sum += i;
  }

  // While loop
  int count = 0;
  while (count < limit / 2) {
    sum += count * 2;
    count++;
  }

  // Do-while loop
  int decrement = limit;
  if (decrement > 0) {
    do {
      sum -= 1;
      decrement--;
    } while (decrement > 0);
  }

  return sum;
}

// Function with multiple local structure variables
void struct_locals() {
  TestStruct s1 = {10, 'S', 1000L};
  TestStruct s2 = {20, 'T', 2000L};
  std::cout << "Local structs: s1.a=" << s1.a << ", s2.b=" << s2.b << std::endl;
}

void complex_struct_locals() {
  ComplexStruct c1 = {{1, 'A', 100L}, &global_int, "Local1"};
  ComplexStruct c2 = {{2, 'B', 200L}, nullptr, "Local2"};
  std::cout << "Complex local structs: c1.name=" << c1.name
            << ", c2.t.c=" << c2.t.c << std::endl;
}

// Entry point
int main(int argc, char** argv) {
  bss_int = argc;
  global_struct.a = argc;
  global_struct.b = 'Z';
  std::cout << "Global struct: " << global_struct.a << " b: " << global_struct.b
            << std::endl;
  std::cout << global_string << std::endl;

  int result = caller_func(bss_int);
  std::cout << "Caller func result: " << result << std::endl;

  int locals_result = compute_locals(10, 5);
  std::cout << "Compute locals result: " << locals_result << std::endl;

  handle_switch(argc);
  handle_switch(42);

  int loop_result = process_loop(10);
  std::cout << "Loop result: " << loop_result << std::endl;

  struct_locals();
  complex_struct_locals();

  if (argc > 100) {
    noreturn_function(argc);
  }

  return 0;
}
