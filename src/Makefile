C++ = g++

ifndef os
   os = LINUX
endif

ifndef arch
   arch = IA32
endif

CCFLAGS = -Wall -D$(os) -I../udt/src -finline-functions -g

ifeq ($(arch), IA32)
   CCFLAGS += -DIA32 #-mcpu=pentiumpro -march=pentiumpro -mmmx -msse
endif

ifeq ($(arch), POWERPC)
   CCFLAGS += -mcpu=powerpc
endif

ifeq ($(arch), IA64)
   CCFLAGS += -DIA64
endif

ifeq ($(arch), SPARC)
   CCFLAGS += -DSPARC
endif

LDFLAGS = -L../src ../udt/src/libudt.a -lstdc++ -lpthread -lm -lssl -lcrypto

ifeq ($(os), UNIX)
   LDFLAGS += -lsocket
endif

ifeq ($(os), SUNOS)
   LDFLAGS += -lrt -lsocket
endif

DIR = $(shell pwd)

APP = udr #test

all: $(APP)

%.o: %.cpp 
	$(C++) $(CCFLAGS) $< -c
udr: udr.o udr_threads.o
	$(C++) $^ -o $@ $(LDFLAGS)

threads_test: threads_test.o
	$(C++) $^ -o $@ $(LDFLAGS)

sig_test: sig_test.o
	$(C++) $^ -o $@ $(LDFLAGS)

sig_test2: sig_test2.o
	$(C++) $^ -o $@ $(LDFLAGS)
#test: test.o
#	$(C++) $^ -o $@ $(LDFLAGS)

clean:
	rm -f *.o $(APP)

install:
	export PATH=$(DIR):$$PATH
