ALL=	libcgi libsnet cgi daemon filters/apache

all:	${ALL}

cgi daemon filters/apache:	libsnet
cgi:	libcgi

${ALL}:	FRC
	cd $@; ${MAKE} ${MFLAGS} all

FRC:

clean install :
	for i in ${ALL}; \
	    do (cd $$i; ${MAKE} ${MFLAGS} $@); \
	done
