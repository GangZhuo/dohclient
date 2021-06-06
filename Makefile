
debug = 0

OBJS = \
	rbtree/rbtree.o \
	http-parser/http_parser.o \
	src/base64url.o \
	src/cache_api.o \
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
	src/netutils.o \
	src/ns_msg.o \
	src/sha1.o \
	src/stream.o \
	src/utils.o \
	src/mleak.o \
	src/ws.o

CFLAGS += -DDOHCLIENT_CACHE_API
LIBS += -lssl -lcrypto
MYLIBS =

ifneq ($(debug), 0)
    CFLAGS += -g -ggdb -DDEBUG -D_DEBUG
    LDFLAGS += -g -ggdb
endif

all: dohclient dohclient-cache

dohclient: $(OBJS) src/main.o
	$(CC) -o $@ $^ $(LDFLAGS) $(LIBS) $(MYLIBS)

dohclient-cache: $(OBJS) src/dohclient-cache.o
	$(CC) -o $@ $^ $(LDFLAGS) $(LIBS) $(MYLIBS)

%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS)

.PHONY : install
install:
	-rm /usr/local/bin/dohclient
	-rm /usr/local/bin/dohclient-cache
	-mkdir -p /usr/local/bin
	cp ./dohclient /usr/local/bin
	cp ./dohclient-cache /usr/local/bin

.PHONY : install-config
install-config:
	-mkdir -p /etc/dohclient
	cp ./asset/chnroute.txt /etc/dohclient
	cp ./asset/chnroute6.txt /etc/dohclient
	cp ./asset/dohclient.config /etc/dohclient

.PHONY : uninstall
uninstall:
	-rm /usr/local/bin/dohclient
	-rm /usr/local/bin/dohclient-cache

.PHONY : uninstall-config
uninstall-config:
	-rm -rf /etc/dohclient

.PHONY: clean
clean:
	-rm -f rbtree/*.o http-parser/*.o src/*.o dohclient dohclient-cache


