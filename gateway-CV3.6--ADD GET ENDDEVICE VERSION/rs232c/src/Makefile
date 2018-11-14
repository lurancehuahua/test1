SUBDIRS=$(shell ls -l | grep ^d | awk '{print $$9}')

CUR_SOURCE=${wildcard *.c}
CUR_OBJS=${patsubst %.c, %.o, $(CUR_SOURCE)}

HEADER_DIR=$(ROOT_DIR)/include


all:$(SUBDIRS) $(CUR_OBJS)
$(SUBDIRS):ECHO
	make -C $@
$(CUR_OBJS):%.o:%.c
	$(CC) $(CCFLAGS) -I$(HEADER_DIR) -c $^ -o $(ROOT_DIR)/$(OBJS_DIR)/$@
ECHO:
	@echo $(SUBDIRS)
