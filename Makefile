CC=	gcc
ALL=	libcgi libsnet cgi html daemon filters/apache
TARGETS= cgi html daemon filters/apache
CFLAGS=

first:	filters/apache
all:	${ALL}

cgi daemon filters/apache:	version.o libsnet
cgi:	libcgi

${ALL}:	version.o FRC
	cd $@; ${MAKE} ${MFLAGS} all

FRC:

clean:
	rm -f version.o
	for i in ${ALL}; \
	    do (cd $$i; ${MAKE} ${MFLAGS} clean); \
	done

VERSION=`date +%Y%m%d`
DISTDIR=../cosign-${VERSION}

dist   : distclean
	mkdir ${DISTDIR}
	tar chfFFX - EXCLUDE . | ( cd ${DISTDIR}; tar xvf - )
	echo ${VERSION} > ${DISTDIR}/VERSION

distclean: clean
	rm -f config.log config.status Makefile libsnet/Makefile \
	libcgi/Makefile cgi/Makefile html/Makefile daemon/Makefile \
	filters/apache/Makefile

install: filters/apache
	cd filters/apache; ${MAKE} ${MFLAGS} install

install-all : all
	for i in ${TARGETS}; \
	    do (cd $$i; ${MAKE} ${MFLAGS} install); \
	done

version.o : version.c
	${CC} ${CFLAGS} -DVERSION=\"`cat VERSION`\" -c version.c
