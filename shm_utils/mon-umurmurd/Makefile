#############################################################################
#
# Makefile for mon-umurmurd


# The recommended compiler flags for the Raspberry Pi
#CCFLAGS=-Wall -Ofast -mfpu=vfp -mfloat-abi=hard -march=armv6zk -mtune=arm1176jzf-s -g -lrt
CCFLAGS= -lrt

# define all programs
PROGRAMS = mon-umurmurd
SOURCES = ${PROGRAMS:=.c}

all: ${PROGRAMS}

${PROGRAMS}: ${SOURCES}
	gcc ${CCFLAGS} $@.c -o $@

clean:
	rm -rf $(PROGRAMS)

install: all


.PHONY: install
