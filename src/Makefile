SRCS:=client.c main.c messages.c pds.c server.c ssl.c log.c conf.c crypt.c \
	timer.c messagehandler.c channel.c Mumble.pb-c.c voicetarget.c

OBJS:=$(patsubst %.c, %.o, $(SRCS))

POLARSSL_LIB:=../../../../polarssl/polarssl-0.12.1/library/libpolarssl.a

# For Valgrind
#CFLAGS:=$(CFLAGS) -I. -I/data/export/proj/openssl/include/ -Wall -g -DDEBUG
#LDFLAGS:=$(LDFLAGS) -L/data/export/proj/openssl/lib/ -lcrypto -lssl -lconfig

# PolarSSL
CFLAGS:=$(CFLAGS) -DDEBUG -DUSE_POLARSSL -I. -I../../../../polarssl/polarssl-0.12.1/include -Wall -g
LDFLAGS:=$(LDFLAGS) -L  -lpolarssl -lconfig

# OpenSSL
#CFLAGS:=$(CFLAGS) -I. -Wall
#LDFLAGS:=$(LDFLAGS) -L  -lcrypto -lssl -lconfig

# Debug
#CFLAGS:=$(CFLAGS) -DDEBUG -I. -Wall -g

# PolarSSL
umurmurd:google/protobuf-c/libprotobuf_c.a depend.mak $(OBJS) $(POLARSSL_LIB)
	$(CC) $(LDFLAGS) $(OBJS) $(POLARSSL_LIB) google/protobuf-c/libprotobuf_c.a -o umurmurd

# OpenSSL
#umurmurd:google/protobuf-c/libprotobuf_c.a depend.mak $(OBJS)
#	$(CC) $(LDFLAGS) $(OBJS) google/protobuf-c/libprotobuf_c.a -o umurmurd

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