CC=	gcc
ALL=	libcgi libsnet cgi cgi/html daemon filters/apache
CFLAGS=

all:	version.o ${ALL}

cgi daemon filters/apache:	libsnet
cgi:	libcgi

${ALL}:	version.o FRC
	cd $@; ${MAKE} ${MFLAGS} all

FRC:

clean:
	rm -f version.o
	for i in ${ALL}; \
	    do (cd $$i; ${MAKE} ${MFLAGS} $@); \
	done

install :
	for i in ${ALL}; \
	    do (cd $$i; ${MAKE} ${MFLAGS} $@); \
	done

version.o : version.c
	${CC} ${CFLAGS} -DVERSION=\"`cat VERSION`\" -c version.c
