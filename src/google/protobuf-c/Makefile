PROTOBUF_SRCS:=protobuf-c.c protobuf-c-data-buffer.c
PROTOBUF_OBJS:=$(patsubst %.c, %.o, $(PROTOBUF_SRCS))
CFLAGS:=$(CFLAGS) -I. -Wall -g

all: libprotobuf_c.a

libprotobuf_c.a:$(PROTOBUF_OBJS)
	$(AR) rcs libprotobuf_c.a $(PROTOBUF_OBJS)

clean:
	rm -f $(PROTOBUF_OBJS) libprotobuf_c.a
