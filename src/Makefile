default: staple

LIB_DIR     = ../lib
BIN_DIR     = ../bin

LDLIBS   += -lz

COMPONENT_DIR = 
ROOT_DIR      = ..
SOURCE_DIR    = $(ROOT_DIR)/src/$(COMPONENT_DIR)
BUILD_DIR     = $(ROOT_DIR)/build/$(COMPONENT_DIR)

SOURCES        := $(wildcard $(SOURCE_DIR)/*.cc $(SOURCE_DIR)/staple/*.cc $(SOURCE_DIR)/staple/http/*.cc $(SOURCE_DIR)/jni/*.cc)
OBJECTS        := $(subst $(ROOT_DIR)/src, $(ROOT_DIR)/build, $(SOURCES:.cc=.o))
STAPLE_SOURCES := $(wildcard $(SOURCE_DIR)/staple/*.cc $(SOURCE_DIR)/staple/http/*.cc $(SOURCE_DIR)/jni/*.cc)
STAPLE_OBJECTS := $(subst $(ROOT_DIR)/src, $(ROOT_DIR)/build, $(STAPLE_SOURCES:.cc=.o))

include Makefile_common.mk

#
# Determine the OS
#
UNAME := $(shell uname)

LIBSTAPLE_SONAME = libstaple.so.2
ifeq ($(UNAME), Linux)
LIBSTAPLE_BUILD_OPTIONS = -shared -Wl,-soname,$(LIBSTAPLE_SONAME) 
endif
ifeq ($(UNAME), Darwin)
LIBSTAPLE_BUILD_OPTIONS = -dynamiclib -single_module
endif

staple: build $(LIB_DIR) $(LIB_DIR)/$(LIBSTAPLE_SONAME) $(BIN_DIR) $(BIN_DIR)/staple

build: $(BUILD_DIR) $(BUILD_DIR)/staple $(BUILD_DIR)/staple/http $(BUILD_DIR)/jni $(OBJECTS)

$(BIN_DIR)/staple: $(OBJECTS) $(LIB_DIR)/$(LIBSTAPLE_SONAME)
	g++ ${CXXFLAGS} ${CFLAGS} -L$(LIB_DIR) -lstaple $(LDLIBS) ../build/Main.o -o $@

$(LIB_DIR)/$(LIBSTAPLE_SONAME): $(STAPLE_OBJECTS)
	g++ ${CPPFLAGS} ${CFLAGS} $(LIBSTAPLE_BUILD_OPTIONS) $(LDLIBS) -fPIC $(STAPLE_OBJECTS) -o $@
	rm -f $(LIB_DIR)/libstaple.so
	cd $(LIB_DIR); ln -s $(LIBSTAPLE_SONAME) libstaple.so

clean:
	rm -fr $(BUILD_DIR) $(LIB_DIR) $(BIN_DIR)
	
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)
	
$(BUILD_DIR)/staple:
	mkdir -p $(BUILD_DIR)/staple
	
$(BUILD_DIR)/staple/http:
	mkdir -p $(BUILD_DIR)/staple/http

$(BUILD_DIR)/jni:
	mkdir -p $(BUILD_DIR)/jni
		
$(LIB_DIR):
	mkdir -p $(LIB_DIR)
	
$(BIN_DIR):
	mkdir -p $(BIN_DIR)
