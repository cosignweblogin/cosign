SRC = cgi.c parse.c token.c
OBJ = cgi.o parse.o token.o

INCPATH=
CFLAGS=	${DEFS} ${OPTOPTS} ${INCPATH} -g
TAGSFILE=	tags
CC=	gcc

LEX=	lex
LEXFLAGS= -t
YACC=	yacc
YFLAGS=	-d -v
LIBS=	-ly -ll -lm

all : libcgi.a

parse.c : parse.y
	${YACC} ${YFLAGS} parse.y
	mv -f y.tab.c parse.c

libcgi.a libcgi_p.a : ${OBJ}
	@echo "building profiled libcgi"
	@cd profiled; ar cru ../libcgi_p.a ${OBJ}
	@ranlib libcgi_p.a
	@echo "building normal libcgi.a"
	@ar cru libcgi.a ${OBJ}
	@ranlib libcgi.a

.c.o :
	${CC} -p ${CFLAGS} -c $*.c
	-ld -r -o $*.o- $*.o
	mv $*.o- profiled/$*.o
	${CC} ${CFLAGS} -c $*.c
	-ld -r -o $*.o- $*.o
	mv $*.o- $*.o

clean :
	rm -f *.o profiled/*.o *.bak *[Ee]rrs tags y.tab.c parse.c token.c
	rm -f libcgi.a libcgi_p.a lex.yy.c y.output y.tab.h

tags : ${SRC}
	cwd=`pwd`; \
	for i in ${SRC}; do \
	    ctags -t -a -f ${TAGSFILE} $$cwd/$$i; \
	done

depend : parse.c token.c
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
