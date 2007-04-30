# a real makefile would have configuration, this is just an example
all: mtoken notoken

mtoken: mtoken.c
	gcc -o mtoken mtoken.c -DLINUX -DUNIX -D_BSD_SOURCE -D_XOPEN_SOURCE=500 -D_POSIX_C_SOURCE=199506 -D_REENTRANT -I/usr/src/ACEAgentSDK/inc /usr/src/ACEAgentSDK/lib/lnx/libaceclnt.a -lpthread

notoken: notoken.c
	gcc -o notoken notoken.c

clean: 
	rm -rf mtoken notoken


