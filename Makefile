LIBS_PATH = /home/users/cse533/Stevens/unpv13e

CC = gcc

LIBS = -lpthread\
	${LIBS_PATH}/libunp.a\

FLAGS = -g -O2

CFLAGS = ${FLAGS} -I${LIBS_PATH}/lib -I.

all: tour_group28 arp_group28 

tour_group28: tour.o get_hw_addrs.o utils.o
	${CC} -o tour_group28 tour.o get_hw_addrs.o utils.o  ${LIBS}

tour.o: tour.c
	${CC} ${CFLAGS} -c tour.c

arp_group28: arp.o get_hw_addrs.o utils.o
	${CC} -o arp_group28 arp.o get_hw_addrs.o utils.o  ${LIBS}

arp.o: arp.c
	${CC} ${CFLAGS} -c arp.c

utils.o: utils.c
	${CC} ${CFLAGS} -c utils.c 

get_hw_addrs.o: get_hw_addrs.c
	${CC} ${FLAGS} -c get_hw_addrs.c

readloop.o: readloop.c
	${CC} ${CFLAGS} -c readloop.c
	
clean:
	rm tour_group28 arp_group28 *.o

