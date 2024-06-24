# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall -g

# Libraries
LIBS = -llua -lpsapi -lkernel32 -lntdll

# Directories
IDIR = -ID:/lua/lua-5.4.6/include
LDIR = -LD:/lua/lua-5.4.6/lib

# Target DLL
DLL_TARGET = winapi.dll

# Source directory
SRCDIR = src

# Source files
SRCS = $(wildcard $(SRCDIR)/*.c)

# Main target (all)
all: $(DLL_TARGET)

$(DLL_TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(IDIR) $(LDIR) -shared -o $@ $^ $(LIBS)

# Rule for compiling .c files to .o files (for executable)
$(SRCDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) $(IDIR) -c -o $@ $<

# Clean target
clean:
	if exist $(DLL_TARGET) del $(DLL_TARGET)

# Phony targets to avoid conflicts with files named 'all' or 'clean'
.PHONY: all clean
