#
# Project name: DCAS
##############################################################################
VERSION = 3
PATCHLEVEL = 5
SUBLEVEL = 3
EXTRAVERSION =

LRD_VERSION = $(VERSION)$(if $(PATCHLEVEL),.$(PATCHLEVEL)$(if $(SUBLEVEL),.$(SUBLEVEL)))$(EXTRAVERSION)

WB ?= wb50n_devel

HOST_DIR ?= $(CURDIR)/../../../../output/$(WB)/host/usr/bin
STAGING_DIR ?= $(CURDIR)/../../../../output/$(WB)/staging
TARGET_DIR ?= $(CURDIR)/../../../../output/$(WB)/target
BASE_DIR := $(CURDIR)

#
# INCLUDE DIRECTORIES AND OPERATING SYSTEM LIBRARY
#
INCLUDES += -I$(STAGING_DIR)/usr/include -Isrc/include -Ilib/flatcc/include
TARGET  = dcas
LDFLAGS = -L$(STAGING_DIR) -L$(STAGING_DIR)/lib -L$(STAGING_DIR)/usr/lib
LIBS = -lc -lssh -lflatccrt -lsdc_sdk

CFLAGS += -Wall --std=c99 -D_LRD_VERSION_STRING=\"$(LRD_VERSION)\"
#
# COMPILER/ASSEMBLER INVOCATIONS
#
# Define RELEASE=1 on the command line to get a release build
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

CC := $(HOST_DIR)/arm-laird-linux-gnueabi-gcc
CXX := $(HOST_DIR)/arm-laird-linux-gnueabi-g++

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

GENERATED = schema/dcal_reader.h

.DONE:


#
# TARGETS
#

.PHONY: all
all : lib/flatcc/bin/flatcc lib/xflatcc/lib/libflatcc.a $(STAGING_DIR)/usr/lib/libflatccrt.a $(TARGET) $(TARGET_DIR)/usr/bin/$(TARGET) keys init.d

$(TARGET) : debug_msg build_msg $(GENERATED) $(OBJECTS)
	$(CC) $(LDFLAGS) -o $(TARGET) $(OBJECTS) $(LIBS)

$(TARGET_DIR)/usr/bin/$(TARGET) : $(TARGET)
	install -D -m 755 $(TARGET) $(TARGET_DIR)/usr/bin/$(TARGET)

schema/dcal_reader.h: schema/dcal.fbs
	cd schema && $(FLATCC) -ca dcal.fbs

.PHONY: $(TARGET)-install
$(TARGET)-install: $(TARGET_DIR)/usr/bin/$(TARGET)

lib:
	mkdir -p lib


#
# FlatCC local
#
flatcc_prep_and_patch_flag: lib/flatcc
	cd lib/flatcc && git checkout v0.2.0
	cd lib/flatcc && patch -p0 < ../../patches/flatcc001_ninja-to-make.patch
	touch flatcc_prep_and_patch_flag

lib/flatcc/bin/flatcc : flatcc_prep_and_patch_flag
	cd lib/flatcc && ./scripts/build.sh

lib/flatcc : lib
	cd lib && git clone git@github.com:dvidelabs/flatcc.git

.PHONY: flatcc
flatcc: lib/flatcc/bin/flatcc

#
# Cross-compiles flatcc
#
xflatcc_prep_and_patch_flag: lib/xflatcc
	cd lib/xflatcc && git checkout v0.2.0
	cd lib/xflatcc && patch -p0 < ../../patches/flatcc001_ninja-to-make.patch
	cd lib/xflatcc && patch -p0 < ../../patches/flatcc002_unaligned.patch
	touch xflatcc_prep_and_patch_flag

lib/xflatcc/lib/libflatcc.a : xflatcc_prep_and_patch_flag
	cd lib/xflatcc && HOST_DIR="$(HOST_DIR)" XTOOLFILE="-DCMAKE_TOOLCHAIN_FILE=$(BASE_DIR)/Toolchain-WB.cmake" ./scripts/build.sh

lib/xflatcc : lib
	cd lib && git clone git@github.com:dvidelabs/flatcc.git xflatcc

$(STAGING_DIR)/usr/lib/libflatccrt.a: lib/xflatcc/lib/libflatccrt.a
	cp -v lib/xflatcc/lib/libflatcc.a $(STAGING_DIR)/usr/lib/libflatcc.a
	cp -v lib/xflatcc/lib/libflatccrt.a $(STAGING_DIR)/usr/lib/libflatccrt.a

.PHONY: xflatcc
xflatcc: lib/xflatcc/lib/libflatcc.a

.PHONY: xflatcc-install
xflatcc-install: $(STAGING_DIR)/usr/lib/libflatccrt.a

#
# Support files
#
keys:
	mkdir -p $(TARGET_DIR)/etc/dcas
	cp -v test/ssh_host_* $(TARGET_DIR)/etc/dcas

init.d:
	install -D -m 755 support/S99dcas $(TARGET_DIR)/etc/init.d/S99dcas
	install -D -m 755 support/loop_dcas.sh $(TARGET_DIR)/usr/bin/loop_dcas.sh

#
# Utility
#

.PHONY: clean
clean :
	-rm -f $(OBJECTS)
	-rm -f $(DEPENDS)
	-rm -f $(TARGET)
	-rm -f schema/*.h
	-rm -rf lib
	-rm -f xflatcc_prep_and_patch_flag
	-rm -f flatcc_prep_and_patch_flag

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
