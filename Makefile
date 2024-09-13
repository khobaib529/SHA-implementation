# Makefile for SHA C++ Implementation
#
# This Makefile builds and manages the benchmarking and unit testing executables for the SHA C++ project.
#
# Targets:
# - `all`: Builds both benchmark and unit test executables.
# - `benchmark`: Compiles the benchmark executable.
# - `unit_tests`: Compiles the unit test executable.
# - `clean`: Removes the build directory and its contents.
#
# Usage:
# - `make`: Builds all targets.
# - `make benchmark`: Builds the benchmark executable.
# - `make unit_tests`: Builds the unit test executable.
# - `make clean`: Cleans up build files.

# Define the compiler and flags
CXX = g++
CXXFLAGS = -std=c++11 -Iinclude -O2

# Define the output directory and files
BUILD_DIR = build

BENCHMARK_SRC = benchmark/sha_benchmark.cpp
BENCHMARK_EXE = $(BUILD_DIR)/benchmark/sha_benchmark

TEST_SRC = test/test_sha.cpp
TEST_EXE = $(BUILD_DIR)/test/test_sha

# Targets and rules
all: benchmark unit_tests

# Build the benchmark executable
benchmark: $(BENCHMARK_SRC)
	@mkdir -p $(BUILD_DIR)
	@mkdir -p $(BUILD_DIR)/benchmark
	$(CXX) $(CXXFLAGS) $(BENCHMARK_SRC) -o $(BENCHMARK_EXE)

# Build the test executable
unit_tests: $(TEST_SRC)
	@mkdir -p $(BUILD_DIR)
	@mkdir -p $(BUILD_DIR)/test
	$(CXX) $(CXXFLAGS) $(TEST_SRC) -o $(TEST_EXE)

# Clean up build files
clean:
	rm -rf $(BUILD_DIR)

# Phony targets
.PHONY: all benchmark clean
