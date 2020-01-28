
debug = 0

OBJS = \
	rbtree/rbtree.o \
	src/channel.o \
	src/channel_cache.o \
	src/channel_os.o \
	src/chnroute.o \
	src/config.o \
	src/dns_request.o \
	src/log.o \
	src/main.o \
	src/netutils.o \
	src/ns_msg.o \
	src/stream.o \
	src/utils.o

CFLAGS +=
MYLIBS =

ifneq ($(debug), 0)
    CFLAGS += -g -DDEBUG -D_DEBUG
    LDFLAGS += -g
endif

all: dohclient

dohclient: $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS) $(LIBS) $(MYLIBS)

%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS)

.PHONY: clean
clean:
	-rm -f src/*.o dohclient


