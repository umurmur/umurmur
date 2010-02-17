SRCS:=client.c main.c messages.c pds.c server.c ssl.c log.c conf.c crypt.c \
	timer.c messagehandler.c channel.c Mumble.pb-c.c voicetarget.c

OBJS:=$(patsubst %.c, %.o, $(SRCS))

# **** Stuff used for debugging ******
# For Valgrind OpenSSL
#EXTRA_CFLAGS:=$(CFLAGS) -I/data/export/proj/openssl/include/
#EXTRA_LDFLAGS:=$(LDFLAGS) -L/data/export/proj/openssl/lib/ -lcrypto -lssl

# Debug
# CFLAGS:=$(CFLAGS) -DDEBUG -g
# ********** Debug stuff END ************


# Build support and link to PolarSSL
# If PolarSSL is in a nonstandard place.
# POLARSSL_LIB:=../../../../polarssl/polarssl-0.12.1/library/libpolarssl.a
# SSL_LIB:=$(POLARSSL_LIB) # If statically linking
# POLARSSL_INCLUDE:=../../../../polarssl/polarssl-0.12.1/include
# EXTRA_CFLAGS:=-DUSE_POLARSSL -I$(POLARSSL_INCLUDE)
# EXTRA_LDLAGS:=-lpolarssl


# OpenSSL - usually installed at a standard place
# EXTRA_CFLAGS:=
# EXTRA_LDFLAGS:=-lcrypto -lssl 

CFLAGS:=$(CFLAGS) -I. -Wall $(EXTRA_CFLAGS)
LDFLAGS:=$(EXTRA_LDFLAGS) $(LDFLAGS) -lconfig 

umurmurd:google/protobuf-c/libprotobuf_c.a $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) $(SSL_LIB) google/protobuf-c/libprotobuf_c.a -o umurmurd

google/protobuf-c/libprotobuf_c.a:
	$(MAKE) -C google/protobuf-c/

clean:
	$(MAKE) -C google/protobuf-c/ clean
	rm -f *.o umurmurd

all: umurmurd

$(OBJS): Makefile

