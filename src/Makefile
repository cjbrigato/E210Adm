CC=g++
CFLAGS=-std=c++17 -I. 

TARGET := E210Adm
OUTPUT := $(TARGET)
SOURCES := $(shell find . -name '*.cpp')
DEPS := $(shell find . -name '*.h')
BUILDDIR := obj
LIBDIR := ../lib
MINIZIP := $(LIBDIR)/minizip/libminizip.a 
ZLIB := $(LIBDIR)/zlib/libzlib.a
LIBOBJECTS := $(MINIZIP) $(ZLIB)

OBJECTS := $(addprefix $(BUILDDIR)/,$(SOURCES:%.cpp=%.o))

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

all: link

static_lut: link
	./E210Adm -g > STATIC_ZOS_SSN_ZIPCRYPTO_LUT.h

link: src
	$(CC) $(OBJECTS) $(LIBOBJECTS) -o $(OUTPUT)

src: objdir $(OBJECTS)

$(BUILDDIR)/%.o: %.cpp
	$(CC) $(CFLAGS) -I$(dir $<) -c $< -o $@

objdir:
	mkdir -p $(BUILDDIR)

clean:
	rm -rf $(BUILDDIR) $(OUTPUT)
