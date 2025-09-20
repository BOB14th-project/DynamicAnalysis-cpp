# Makefile for OpenSSL AES-GCM Coverage Test
# Simple OpenSSL-based encryption example for coverage analysis

# Compiler settings
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2
DEBUG_FLAGS = -g -DDEBUG
COVERAGE_FLAGS = --coverage -fprofile-arcs -ftest-coverage
RELEASE_FLAGS = -O3 -DNDEBUG

# Library settings (only OpenSSL needed)
LIBS = -lssl -lcrypto

# Directories
SRC_DIR = .
BUILD_DIR = build
COVERAGE_DIR = coverage

# Source files
SOURCES = coverage_test.cpp
OBJECTS = $(SOURCES:%.cpp=$(BUILD_DIR)/%.o)
TARGET = coverage_test

# Coverage files
GCDA_FILES = $(SOURCES:%.cpp=$(BUILD_DIR)/%.gcda)
GCNO_FILES = $(SOURCES:%.cpp=$(BUILD_DIR)/%.gcno)

# Default target
.PHONY: all
all: $(TARGET)

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Create coverage directory
$(COVERAGE_DIR):
	mkdir -p $(COVERAGE_DIR)

# Build release version
$(TARGET): $(BUILD_DIR) $(OBJECTS)
	$(CXX) $(CXXFLAGS) $(OBJECTS) $(LIBS) -o $(TARGET)

# Build object files
$(BUILD_DIR)/%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Debug build
.PHONY: debug
debug: CXXFLAGS += $(DEBUG_FLAGS)
debug: $(TARGET)

# Coverage build
.PHONY: coverage
coverage: CXXFLAGS += $(COVERAGE_FLAGS)
coverage: $(BUILD_DIR) $(COVERAGE_DIR)
	$(CXX) $(CXXFLAGS) $(SOURCES) $(LIBS) -o $(BUILD_DIR)/$(TARGET)_coverage

# Release build (optimized)
.PHONY: release
release: CXXFLAGS += $(RELEASE_FLAGS)
release: $(TARGET)

# Run the program
.PHONY: run
run: $(TARGET)
	./$(TARGET)

# Run debug version
.PHONY: run-debug
run-debug: debug
	gdb ./$(TARGET)

# Run coverage analysis
.PHONY: run-coverage
run-coverage: coverage
	@echo "Running coverage analysis..."
	cd $(BUILD_DIR) && ./$(TARGET)_coverage
	cd $(BUILD_DIR) && gcov ../$(SOURCES)
	mkdir -p $(COVERAGE_DIR)
	mv $(BUILD_DIR)/*.gcov $(COVERAGE_DIR)/
	@echo "Coverage files generated in $(COVERAGE_DIR)/"

# Generate HTML coverage report (requires lcov)
.PHONY: coverage-html
coverage-html: run-coverage
	@echo "Generating HTML coverage report..."
	lcov --capture --directory $(BUILD_DIR) --output-file $(COVERAGE_DIR)/coverage.info
	genhtml $(COVERAGE_DIR)/coverage.info --output-directory $(COVERAGE_DIR)/html
	@echo "HTML coverage report generated in $(COVERAGE_DIR)/html/"

# Profile with gprof
.PHONY: profile
profile: CXXFLAGS += -pg
profile: $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $(SOURCES) $(LIBS) -o $(BUILD_DIR)/$(TARGET)_profile
	cd $(BUILD_DIR) && ./$(TARGET)_profile
	cd $(BUILD_DIR) && gprof ./$(TARGET)_profile gmon.out > profile_report.txt
	@echo "Profile report generated in $(BUILD_DIR)/profile_report.txt"

# Static analysis with cppcheck
.PHONY: static-analysis
static-analysis:
	@echo "Running static analysis with cppcheck..."
	cppcheck --enable=all --std=c++17 --verbose $(SOURCES)

# Memory check with valgrind
.PHONY: memcheck
memcheck: debug
	valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ./$(TARGET)

# Performance test
.PHONY: perf-test
perf-test: release
	@echo "Running performance test..."
	time ./$(TARGET)

# Code formatting with clang-format
.PHONY: format
format:
	clang-format -i $(SOURCES)

# Clean build artifacts
.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
	rm -f $(TARGET)
	rm -f *.gcda *.gcno *.gcov

# Clean all generated files including coverage
.PHONY: clean-all
clean-all: clean
	rm -rf $(COVERAGE_DIR)
	rm -f gmon.out

# Install dependencies (Ubuntu/Debian)
.PHONY: install-deps
install-deps:
	sudo apt-get update
	sudo apt-get install -y build-essential g++ gdb valgrind cppcheck
	sudo apt-get install -y lcov clang-format
	sudo apt-get install -y libssl-dev

# Install dependencies (CentOS/RHEL)
.PHONY: install-deps-centos
install-deps-centos:
	sudo yum groupinstall -y "Development Tools"
	sudo yum install -y gcc-c++ gdb valgrind cppcheck lcov
	sudo yum install -y openssl-devel

# Test all configurations
.PHONY: test-all
test-all: clean
	@echo "Testing debug build..."
	$(MAKE) debug && ./$(TARGET)
	@echo "Testing release build..."
	$(MAKE) clean && $(MAKE) release && ./$(TARGET)
	@echo "Testing coverage build..."
	$(MAKE) clean && $(MAKE) run-coverage
	@echo "All tests completed successfully!"

# Continuous integration target
.PHONY: ci
ci: clean static-analysis test-all coverage-html
	@echo "CI pipeline completed successfully!"

# Show help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  all             - Build release version (default)"
	@echo "  debug           - Build debug version with debug symbols"
	@echo "  release         - Build optimized release version"
	@echo "  coverage        - Build with coverage instrumentation"
	@echo "  run             - Run the program"
	@echo "  run-debug       - Run with gdb debugger"
	@echo "  run-coverage    - Run coverage analysis and generate reports"
	@echo "  coverage-html   - Generate HTML coverage report (requires lcov)"
	@echo "  profile         - Build and run with profiling (gprof)"
	@echo "  static-analysis - Run static code analysis (cppcheck)"
	@echo "  memcheck        - Run memory leak detection (valgrind)"
	@echo "  perf-test       - Run performance test"
	@echo "  format          - Format code with clang-format"
	@echo "  test-all        - Test all build configurations"
	@echo "  ci              - Run full CI pipeline"
	@echo "  clean           - Remove build artifacts"
	@echo "  clean-all       - Remove all generated files"
	@echo "  install-deps    - Install dependencies (Ubuntu/Debian)"
	@echo "  install-deps-centos - Install dependencies (CentOS/RHEL)"
	@echo "  help            - Show this help message"

# Phony targets to avoid conflicts with files
.PHONY: clean clean-all help install-deps install-deps-centos
.PHONY: static-analysis memcheck perf-test format test-all ci