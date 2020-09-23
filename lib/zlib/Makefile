CC=gcc
CFLAGS=-I.

TARGET := libzlib
OUTPUT := $(TARGET).a
SOURCES := $(shell find . -name '*.c')
DEPS := $(shell find . -name '*.h')
BUILDDIR := obj

OBJECTS := $(addprefix $(BUILDDIR)/,$(SOURCES:%.c=%.o))

ifeq '$(findstring ;,$(PATH))' ';'
    UNAME := Windows
else
    UNAME := $(shell uname 2>/dev/null || echo Unknown)
    UNAME := $(patsubst CYGWIN%,Cygwin,$(UNAME))
    UNAME := $(patsubst MSYS%,MSYS,$(UNAME))
    UNAME := $(patsubst MINGW%,MSYS,$(UNAME))
endif

ifeq ($(UNAME),Darwin)
    ARCOMMAND := ar -rv $(OUTPUT) $(OBJECTS)
else
    ARCOMMAND := ar rcs $(OUTPUT) -o $(OBJECTS)
endif

all: $(TARGET)

$(TARGET): objdir $(OBJECTS)
	ar -rv $(OUTPUT) $(OBJECTS)

$(BUILDDIR)/%.o: %.c
	$(CC) $(CFLAGS) -I$(dir $<) -c $< -o $@

objdir:
	mkdir -p $(BUILDDIR)

clean:
	rm -rf $(BUILDDIR) $(OUTPUT)
