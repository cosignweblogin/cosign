################## Some of this may need to be edited ##################

DESTDIR=/usr/local
MANDIR=${DESTDIR}/man
BINDIR=${DESTDIR}/bin
ETCDIR=${DESTDIR}/etc
SBINDIR=${DESTDIR}/sbin

COSIGNLOG=LOG_LOCAL7

# Stock compiler:
#CC=	cc

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

INCPATH=	-Ilibsnet -I/usr/local/openssl/include
DEFS=	-DLOG_COSIGN=${COSIGNLOG} -DTLS
CFLAGS=	${DEFS} ${OPTOPTS} ${INCPATH}
TAGSFILE=	tags
LIBPATH=	-Llibsnet -L/usr/local/openssl/lib
LIBS=	${ADDLIBS} -lsnet -lssl -lcrypto

TARGETS=	cosignd

all : ${TARGETS}

daemon.o : daemon.c
	${CC} ${CFLAGS} -DVERSION=\"`cat VERSION`\" -c daemon.c

cosignd : libsnet/libsnet.a ${COSIGNOBJ} Makefile
	${CC} ${CFLAGS} ${LDFLAGS} -o cosignd ${COSIGNOBJ} ${LIBPATH} ${LIBS}

FRC :

libsnet/libsnet.a : FRC
	cd libsnet; ${MAKE} ${MFLAGS} CC=${CC} DEFS="${DEFS}" \
		INCPATH="${INCPATH}"

VERSION=`date +%Y%m%d`
DISTDIR=../cosign-${VERSION}

dist : clean
	mkdir ${DISTDIR}
	tar chfFFX - EXCLUDE . | ( cd ${DISTDIR}; tar xvf - )
	chmod +w ${DISTDIR}/Makefile
	echo ${VERSION} > ${DISTDIR}/VERSION

clean :
	cd libsnet; ${MAKE} ${MFLAGS} clean
	rm -f a.out core* *.o *.bak *[Ee]rrs tags
	rm -f ${TARGETS}

tags : ${SRC}
	cwd=`pwd`; \
	for i in ${SRC}; do \
	    ctags -t -a -f ${TAGSFILE} $$cwd/$$i; \
	done

depend :
	for i in ${SRC} ; do \
	    ${CC} -M ${DEFS} ${INCPATH} $$i | \
	    awk ' { if ($$1 != prev) { print rec; rec = $$0; prev = $$1; } \
		else { if (length(rec $$2) > 78) { print rec; rec = $$0; } \
		else rec = rec " " $$2 } } \
		END { print rec } ' >> makedep; done
	sed -n '1,/^# DO NOT DELETE THIS LINE/p' Makefile > Makefile.tmp
	cat makedep >> Makefile.tmp
	rm makedep
	echo '# DEPENDENCIES MUST END AT END OF FILE' >> Makefile.tmp
	echo '# IF YOU PUT STUFF HERE IT WILL GO AWAY' >> Makefile.tmp
	echo '# see make depend above' >> Makefile.tmp
	rm -f Makefile.bak
	cp Makefile Makefile.bak
	mv Makefile.tmp Makefile

# DO NOT DELETE THIS LINE
