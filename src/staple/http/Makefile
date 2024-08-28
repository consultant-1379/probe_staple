httpall: http

COMPONENT_DIR = staple/http
ROOT_DIR      = ../../..
SOURCE_DIR    = $(ROOT_DIR)/src/$(COMPONENT_DIR)
BUILD_DIR     = $(ROOT_DIR)/build/$(COMPONENT_DIR)

SOURCES := $(wildcard $(SOURCE_DIR)/*.cc)
OBJECTS := $(subst $(ROOT_DIR)/src, $(ROOT_DIR)/build, $(SOURCES:.cc=.o))
 
include ../../Makefile_common.mk

http: $(BUILD_DIR) $(OBJECTS)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)
	
clean:
	rm -fr $(BUILD_DIR)