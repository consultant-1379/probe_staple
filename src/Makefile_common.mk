# Variables for paths
INCLUDES += -I$(ROOT_DIR)/include -I$(ROOT_DIR)/include/jni

# Default config
CFLAGS = -g -O2 -fPIC -Wall
CXXFLAGS = -pthread -std=c++0x

# Optimize
# CFLAGS = -g -O2
# Debug
# CFLAGS = -O0 -ggdb3
# CFLAGS += -Wall
# Profile
# CFLAGS = -pg
# Valgrind
# CFLAGS = -g -O1
# With Google Perftools' malloc library
# LDLIBS += -ltcmalloc

$(BUILD_DIR)/%.o : %.cc
	g++ $(CXXFLAGS) $(CFLAGS) $(INCLUDES) -MD -c $< -o $@
	sed 's/\.\.[\/\.]*\//$$(ROOT_DIR)\//g' $(@D)/$(*F).d > $(@D)/$(*F).d.tmp; \
	mv $(@D)/$(*F).d.tmp $(@D)/$(*F).d; \
	cp $(@D)/$(*F).d $(@D)/$(*F).P; \
	sed -e 's/#.*//' -e 's/^[^:]*: *//' -e 's/ *\\$$//' \
		-e '/^$$/ d' -e 's/$$/ :/' < $(@D)/$(*F).d >> $(@D)/$(*F).P; \
	rm -f $(@D)/$(*F).d

-include $(OBJECTS:%.o=%.P)
