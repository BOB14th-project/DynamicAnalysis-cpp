# ===== Toolchain =====
CXX       ?= g++
CXXFLAGS  ?= -std=c++17 -O2 -Wall -Wextra

# ===== Layout =====
BIN_DIR    := bin
RUNNER_SRC ?= runner.cpp
RUNNER_BIN := $(BIN_DIR)/runner

# 기본 출력 파일(원하면 바꿔서 실행 가능: make run OUT=logs.ndjson)
OUT ?= events.ndjson
AGENT ?= ./agent.js
TARGET ?=

.PHONY: all clean run print-vars deps-check

all: $(RUNNER_BIN)

$(BIN_DIR):
	@mkdir -p $@

$(RUNNER_BIN): $(RUNNER_SRC) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $< -o $@

# 실행: make run TARGET=/mnt/d/aes_256_cbc [AGENT=./agent.js] [OUT=events.ndjson] [ARGS="..."]
run: $(RUNNER_BIN)
	@if [ -z "$(TARGET)" ]; then \
		echo "ERROR: Please provide TARGET=/path/to/elf"; exit 2; \
	fi
	@if [ ! -f "$(AGENT)" ]; then \
		echo "ERROR: agent file not found: $(AGENT)"; exit 2; \
	fi
	./$(RUNNER_BIN) --target "$(TARGET)" --agent "$(AGENT)" --out "$(OUT)" -- $(ARGS)

print-vars:
	@echo CXX='$(CXX)'
	@echo CXXFLAGS='$(CXXFLAGS)'
	@echo RUNNER_SRC='$(RUNNER_SRC)'
	@echo RUNNER_BIN='$(RUNNER_BIN)'
	@echo TARGET='$(TARGET)'
	@echo AGENT='$(AGENT)'
	@echo OUT='$(OUT)'
	@echo ARGS='$(ARGS)'

deps-check:
	@echo "frida: $$(command -v frida || echo MISSING)"
	@echo "Tip: pip install frida-tools"

clean:
	@rm -rf $(BIN_DIR) $(OUT)
