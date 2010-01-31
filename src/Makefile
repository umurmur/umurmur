SRCS:=client.c main.c messages.c pds.c server.c ssl.c log.c conf.c crypt.c \
	timer.c messagehandler.c channel.c Mumble.pb-c.c voicetarget.c

OBJS:=$(patsubst %.c, %.o, $(SRCS))

#CFLAGS:=$(CFLAGS) -I. -I/data/export/proj/openssl/include/ -Wall -g -DDEBUG
#LDFLAGS:=$(LDFLAGS) -L/data/export/proj/openssl/lib/ -lcrypto -lssl -lconfig
CFLAGS:=$(CFLAGS) -I. -Wall -g
LDFLAGS:=$(LDFLAGS) -lcrypto -lssl -lconfig

umurmurd:google/protobuf-c/libprotobuf_c.a depend.mak $(OBJS)  
	$(CC) $(LDFLAGS) $(OBJS) google/protobuf-c/libprotobuf_c.a -o umurmurd

google/protobuf-c/libprotobuf_c.a:
	$(MAKE) -C google/protobuf-c/

clean:
	$(MAKE) -C google/protobuf-c/ clean
	rm -f *.o umurmurd depend.mak

all: umurmurd

$(OBJS): Makefile

depend.mak:
	$(CC) $(CFLAGS) -M $(SRCS) > depend.mak

include depend.mak