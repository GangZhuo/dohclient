debug = 0

OBJS = src/log.o \
       src/stream.o \
	   src/chnroute.o \
	   src/dnscache.o \
	   http-parser/http_parser.o \
	   rbtree/rbtree.c

CFLAGS += -DASYN_DNS
MY_LIBS += -lcares

ifneq ($(debug), 0)
    CFLAGS += -g -DDEBUG -D_DEBUG
    LDFLAGS += -g
endif

all: dohclient

dohclient: src/main.o $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS) $(LIBS) $(MY_LIBS)

%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS)

.PHONY: clean
clean:
	-rm -f src/*.o dohclient


