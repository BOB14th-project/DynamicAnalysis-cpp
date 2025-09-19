# Compiler settings
CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++17 -O2
DEBUGFLAGS = -g -DDEBUG

# Target executable
TARGET = aes_256_cbc

# Source files
SOURCES = aes_256_cbc.cpp

# Object files
OBJECTS = $(SOURCES:.cpp=.o)

# OpenSSL library flags (Linux)
LIBS = -lssl -lcrypto

# Default target
all: $(TARGET)

# Build the executable
$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJECTS) $(LIBS)

# Build object files
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Debug build
debug: CXXFLAGS += $(DEBUGFLAGS)
debug: $(TARGET)

# Clean build files
clean:
	rm -f $(TARGET) $(OBJECTS)

# Clean and rebuild
rebuild: clean all

# Install target (optional)
install: $(TARGET)
	mkdir -p ../bin
	cp $(TARGET) ../bin/

# Help
help:
	@echo "Available targets:"
	@echo "  all      - Build the executable (default)"
	@echo "  debug    - Build with debug flags"
	@echo "  clean    - Remove build files"
	@echo "  rebuild  - Clean and rebuild"
	@echo "  install  - Copy executable to bin directory"
	@echo "  help     - Show this help"

.PHONY: all debug clean rebuild install help