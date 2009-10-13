#makefile
CCM=g++
CCMFLAGS=-std=c++98 -Wall -pedantic

all:  isa clean

isa: isa.c
	$(CCM) $(CCMFLAGS) isa.c -o $@

clean:
	rm -f *.o

