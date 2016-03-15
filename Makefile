#
# Project name: DCAS
##############################################################################
VERSION = 3
PATCHLEVEL = 5
SUBLEVEL = 3
EXTRAVERSION =

LRD_VERSION = $(VERSION)$(if $(PATCHLEVEL),.$(PATCHLEVEL)$(if $(SUBLEVEL),.$(SUBLEVEL)))$(EXTRAVERSION)

#
# INCLUDE DIRECTORIES AND OPERATING SYSTEM LIBRARY
#
INCLUDES += -Isrc/include -Ilib/flatcc/include
TARGET  = dcas
LDFLAGS = -Llib/flatcc/lib
LIBS = -lssh -lflatccrt -lsdc_sdk -lpthread

CPPCHECK := $(shell cppcheck --version 2>/dev/null)
CPPCHECK_FLAGS = --enable=all --suppress=missingIncludeSystem --std=c99 $(INCLUDES)
CHECK_ARGS =

CFLAGS += -Wall -Werror --std=c99 -D_LRD_VERSION_STRING=\"$(LRD_VERSION)\"
#
# COMPILER/ASSEMBLER INVOCATIONS
#
# Define RELEASE=1 on the command line to get 
# We redefine CC to ensure gcc is used as 'cc' is the make default
ifdef RELEASE
  CFLAGS +=  -O3 $(INCLUDES)
  CXXFLAGS +=  -O3 $(INCLUDES)
else
  define DEBUGTXT
    @printf "\n#\n# Define RELEASE=1 on the command line to compile release version.\n"
    @printf "# Assuming debug compile. \n#\n"
  endef
  CFLAGS += -ggdb -fno-inline -DDEBUG_BUILD $(INCLUDES)
  CXXFLAGS += -ggdb -fno-inline -DDEBUG_BUILD $(INCLUDES)
endif

# if we haven't defined the path to the FLATCC tool, then use the one we
# hopefully generated. For buildroot, this should be passed in preset, typically:
#   FLATCC="$(HOST_DIR)/usr/bin/flatcc"
FLATCC ?= ../lib/flatcc/bin/flatcc

CC ?= gcc
CXX ?= g++

#
# Source and object files
#
SOURCES := $(wildcard src/*.cpp src/*.c)
OBJECTS := $(addsuffix .o,$(basename $(SOURCES)))
DEPENDS := $(addsuffix .d,$(basename $(SOURCES)))

#
# GENERATION RULES
#
# These automatically create all of your object files
# and depencency files as long as you have your OBJECTS
# setup right

%.o: %.cpp
	$(COMPILE.cpp) -D FLATCC_PORTABLE -MMD -MP -o $@ $<

%.o: %.c
	$(COMPILE.c) -D FLATCC_PORTABLE -MMD -MP -o $@ $<

GENERATED = 	schema/dcal_reader.h

.DONE:


#
# TARGETS
#

.PHONY: all
all : static unit $(TARGET) check

$(TARGET) : debug_msg build_msg $(GENERATED) $(OBJECTS)
	$(CC) $(LDFLAGS) -o $(TARGET) $(OBJECTS) $(LIBS)

schema/dcal_reader.h : schema/dcal.fbs
	cd schema && $(FLATCC) -ca dcal.fbs




.PHONY: static
static :
	@printf "\n#\n# Doing static analysis\n#\n"
ifdef CPPCHECK
	@echo "ccpcheck version $(CPPCHECK)"
	cppcheck $(CPPCHECK_FLAGS) src
else
	    @echo ccpcheck not found - skipping
endif

.PHONY: unit
unit:
	@printf "\n#\n# Doing unit tests\n#\n"

.PHONY: check
check:
	@printf "\n#\n# Doing run test\n#\n"
	@./$(TARGET) $(CHECK_ARGS) || (printf "\n==========================================\n|||| $(TARGET) run failed $$?\a\n\n"; exit 1)

#
# Library builds
#
lib:
	mkdir -p lib

lib/libssh: lib
	cd lib && git clone git://git.libssh.org/projects/libssh.git

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
	LIBSSH_TARGET := lib/libssh/build/src/libssh.so.4.4.0
endif
ifeq ($(UNAME_S),Darwin)
	LIBSSH_TARGET := lib/libssh/build/src/libssh.4.4.0.dylib
endif
$(LIBSSH_TARGET): lib lib/libssh
	cd lib/libssh && git checkout 4d43fbfb50710055352c4fda812b6dc98143d336
	mkdir -p lib/libssh/build
	cd lib/libssh/build && cmake ..
	cd lib/libssh/build && make

.PHONY: libssh
libssh: $(LIBSSH_TARGET)

libssh_install: $(LIBSSH_TARGET)
	cd lib/libssh/build && make install

lib/flatcc/lib/libflatcc.a : lib/flatcc
	cd lib/flatcc && git checkout v0.2.0
	cd lib/flatcc && patch -p0 < ../../patches/flatcc001_ninja-to-make.patch
	cd lib/flatcc && ./scripts/build.sh

lib/flatcc : lib
	cd lib && git clone git@github.com:dvidelabs/flatcc.git

.PHONY: flatcc
flatcc: lib/flatcc/lib/libflatcc.a

#
# Tools/testing
#
test/client/dcas-client:
	cd test/client && make

.PHONY: do-dcas-test
do-dcas-test:
	cd test/client && make check

.PHONY: dcas-test
dcas-test: test/client/dcas-client do-dcas-test

#
# Utility
#

.PHONY: clean
clean :
	-rm -f $(OBJECTS)
	-rm -f $(DEPENDS)
	-rm -f $(TARGET)
	-rm -f schema/*.h

.PHONY: cleanall
cleanall: clean

.PHONY: build_msg
build_msg:
	@printf "#\n# Building $(TARGET)\n#\n"
        
.PHONY: debug_msg
debug_msg:
	$(DEBUGTXT)

# help 
.PHONY: help
help:
	@make --print-data-base --question | \
	awk '/^[^.%][-A-Za-z0-9_]*:/ \
	{ print substr($$1, 1, length($$1)-1) }' | \
	sort | \
	pr --omit-pagination --width=80 --columns=4

ifdef DUMPVARS
$(foreach v, $(.VARIABLES), $(info $(v) = $($(v))))
endif

# dependency generation
ifneq "$(MAKECMDGOALS)" "clean"
  -include $(addsuffix .d,$(basename $(SOURCES)))
endif
