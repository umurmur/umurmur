# build helloworld executable when user executes "make" 

SRCS:=client.c main.c messages.c pds.c server.c ssl.c log.c conf.c crypt.c \
	timer.c messagehandler.c channel.c Mumble.pb-c.c

OBJS:=$(patsubst %.c, %.o, $(SRCS))
CFLAGS:=$(CFLAGS) -I. -Wall -g -DDEBUG
LDFLAGS:=$(LDFLAGS) -L/data/export/proj/protobuf/lib -lcrypto -lssl -lconfig

umurmurd:google/protobuf-c/libprotobuf_c.a depend.mak $(OBJS)  
	$(CC) $(LDFLAGS) $(OBJS) google/protobuf-c/libprotobuf_c.a -o umurmurd

google/protobuf-c/libprotobuf_c.a:
	$(MAKE) -C google/protobuf-c/

# remove object files and executable when user executes "make clean"
clean:
	$(MAKE) -C google/protobuf-c/ clean
	rm -f *.o umurmurd 

all: umurmurd

$(OBJS): Makefile

depend.mak:
	$(CC) -M $(SRCS) > depend.mak

include depend.mak