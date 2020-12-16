
debug = 0

OBJS = \
	rbtree/rbtree.o \
	http-parser/http_parser.o \
	src/base64url.o \
	src/channel.o \
	src/channel_cache.o \
	src/channel_chndoh.o \
	src/channel_doh.o \
	src/channel_os.o \
	src/channel_tcp.o \
	src/channel_udp.o \
	src/channel_hosts.o \
	src/chnroute.o \
	src/config.o \
	src/dns_request.o \
	src/http.o \
	src/log.o \
	src/main.o \
	src/netutils.o \
	src/ns_msg.o \
	src/stream.o \
	src/utils.o \
	src/mleak.o

CFLAGS +=
LIBS += -lssl -lcrypto
MYLIBS =

ifneq ($(debug), 0)
    CFLAGS += -g -ggdb -DDEBUG -D_DEBUG
    LDFLAGS += -g -ggdb
endif

all: dohclient

dohclient: $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS) $(LIBS) $(MYLIBS)

%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS)

.PHONY : install
install:
	cp ./dohclient /usr/local/bin

.PHONY : uninstall
uninstall:
	rm /usr/local/bin/dohclient

.PHONY: clean
clean:
	-rm -f rbtree/*.o
	-rm -f http-parser/*.o
	-rm -f src/*.o dohclient


