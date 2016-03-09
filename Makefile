#
# Project name: DCAS
##############################################################################

#
# INCLUDE DIRECTORIES AND OPERATING SYSTEM LIBRARY
#
INCLUDES = #-I and then include paths
TARGET  = dcas
LDFLAGS =
LIBS =

#
# COMPILER/ASSEMBLER INVOCATIONS
#
# Define RELEASE=1 on the command line to get 
# We redefine CC to ensure gcc is used as 'cc' is the make default
ifdef RELEASE
  CFLAGS += -Wall -O3 $(INCLUDES)
  CXXFLAGS += -Wall -O3 $(INCLUDES)
else
  define DEBUGTXT
    @printf "\n#\n# Define RELEASE=1 on the command line to compile release version.\n"
    @printf "# Assuming debug compile. \n#\n"
  endef
  CFLAGS += -ggdb -fno-inline -Wall -DDEBUG_BUILD $(INCLUDES)
  CXXFLAGS += -ggdb -fno-inline -Wall -DDEBUG_BUILD $(INCLUDES)
endif

CC = gcc
CXX = g++

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
	$(COMPILE.cpp) -MMD -MP -o $@ $<

%.o: %.c
	$(COMPILE.c) -MMD -MP -o $@ $<

.DONE:


#
# TARGETS
#

$(TARGET) : debug_msg build_msg $(OBJECTS)
	$(CXX) $(LDFLAGS) -o $(TARGET) $(OBJECTS) $(LIBS)

.PHONY: all
all : $(TARGET)

.PHONY: check
check : test.sh $(TARGET)
	bash ./test.sh

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
	
# dependency generation
ifneq "$(MAKECMDGOALS)" "clean"
  -include $(addsuffix .d,$(basename $(SOURCES)))
endif
