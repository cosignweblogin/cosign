################## Some of this may need to be edited ##################

DESTDIR=/usr/local
MANDIR=${DESTDIR}/man
BINDIR=${DESTDIR}/bin
ETCDIR=${DESTDIR}/etc
SBINDIR=${DESTDIR}/sbin

COSIGNLOG=LOG_LOCAL7

# For gcc:
CC=	gcc
# These options might work on your system:
OPTOPTS=-Wall -Wmissing-prototypes -Wconversion

# For most platforms:
INSTALL=	install

# For Solaris:
#INSTALL=	/usr/ucb/install
ADDLIBS=	-lsocket -lnsl

################ Nothing below should need editing ###################

SRC=    daemon.c command.c argcargv.c cparse.c
COSIGNOBJ=	daemon.o command.o argcargv.o cparse.o

INCPATH=	-I../libsnet -I/usr/local/openssl/include
DEFS=	-DLOG_COSIGN=${COSIGNLOG} -DTLS
CFLAGS=	${DEFS} ${OPTOPTS} ${INCPATH}
TAGSFILE=	tags
LIBPATH=	-L../libsnet -L/usr/local/openssl/lib
LIBS=	${ADDLIBS} -lsnet -lssl -lcrypto

TARGETS=	cosignd

all : ${TARGETS}

daemon.o : daemon.c
	${CC} ${CFLAGS} -DVERSION=\"`cat ../VERSION`\" -c daemon.c

cosignd : ../libsnet/libsnet.a ${COSIGNOBJ} Makefile
	${CC} ${CFLAGS} ${LDFLAGS} -o cosignd ${COSIGNOBJ} ${LIBPATH} ${LIBS}

clean :
	rm -f a.out core* *.o *.bak *[Ee]rrs tags
	rm -f ${TARGETS}
