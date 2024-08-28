stapleall: staple

COMPONENT_DIR = staple
ROOT_DIR      = ../..
SOURCE_DIR    = $(ROOT_DIR)/src/$(COMPONENT_DIR)
BUILD_DIR     = $(ROOT_DIR)/build/$(COMPONENT_DIR)

SOURCES := $(wildcard $(SOURCE_DIR)/*.cc $(SOURCE_DIR)/http/*.cc)
OBJECTS := $(subst $(ROOT_DIR)/src, $(ROOT_DIR)/build, $(SOURCES:.cc=.o))
 
include ../Makefile_common.mk

staple: $(BUILD_DIR) $(BUILD_DIR)/http $(OBJECTS)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)
	
$(BUILD_DIR)/http:
	mkdir -p $(BUILD_DIR)/http
	
clean:
	rm -fr $(BUILD_DIR)