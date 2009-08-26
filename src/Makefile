# build helloworld executable when user executes "make" 

SRCS:=client.c main.c messages.c pds.c server.c ssl.c log.c conf.c crypt.c timer.c messagehandler.c channel.c
OBJS:=$(patsubst %.c, %.o, $(SRCS))
CFLAGS:=$(CFLAGS) -Wall -Os -g
LDFLAGS:=$(LDFLAGS) -lcrypto -lssl -lconfig

umurmurd:$(OBJS) depend.mak
	$(CC) $(LDFLAGS) $(OBJS) -o umurmurd

# remove object files and executable when user executes "make clean"
clean:
	rm *.o umurmurd 

all: umurmur

$(OBJS): Makefile

depend.mak:
	$(CC) -M $(SRCS) > depend.mak

include depend.mak