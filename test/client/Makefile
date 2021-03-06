#
# Project name: DCAS-client
##############################################################################
#
# INCLUDE DIRECTORIES AND OPERATING SYSTEM LIBRARY
#
INCLUDES = -I../../src/include  -I../../lib.local/flatcc/include
TARGET  = dcas-client
LDFLAGS = -L../../lib.local/flatcc/lib
LIBS = -lssh -lflatccrt

CPPCHECK_FLAGS = --enable=all --suppress=missingIncludeSystem --std=c99
CHECK_ARGS = -h 127.0.0.1 -p 2222 -u libssh -P libssh

CFLAGS += -Wall -Werror --std=c99
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

CC = gcc
CXX = g++

#
# Source and object files
#
SOURCES := $(wildcard *.cpp *.c)
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

GENERATED = 	../../schema/dcal_reader.h

.DONE:


#
# TARGETS
#

.PHONY: all
all : $(GENERATED) static $(TARGET) check

$(TARGET) : debug_msg build_msg $(OBJECTS)
	$(CXX) $(LDFLAGS) -o $(TARGET) $(OBJECTS) $(LIBS)

../../schema/dcal_reader.h : ../../schema/dcal.fbs
	cd ../../schema && ../lib.local/flatcc/bin/flatcc -ca dcal.fbs

.PHONY: static
static :
	@printf "\n#\n# Doing static analysis\n#\n"
	cppcheck $(CPPCHECK_FLAGS) .

.PHONY: check
check:
	@printf "\n#\n# Doing run test\n#\n"
	@./$(TARGET) $(CHECK_ARGS) || (printf "\n==========================================\n|||| $(TARGET) run failed $$?\a\n\n"; exit 1)

.PHONY: clean
clean :
	-rm -f $(OBJECTS)
	-rm -f $(DEPENDS)
	-rm -f $(TARGET)

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
