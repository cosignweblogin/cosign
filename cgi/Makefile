CGIBIN	= /usr/local/projects/cosign/cgi-ssl
TMPL	= /usr/local/projects/cosign/templates/
HTML	= /usr/local/projects/cosign/html/

CC	= gcc
TARGETS	= cosign logout
OBJ	= mkcookie.o fbase64.o network.o

KDIR	= /usr/local/krb5
KLIBDIR	= $(KDIR)/lib
KINCDIR	= $(KDIR)/include
#KLIBS	= $(KLIBDIR)/libkrb.a $(KLIBDIR)/libdes.a
EX_LIBS	= -lsocket -lnsl -lresolv

INC	= -Ilibcgi -I/afs/umich.edu/group/itd/software/packages/k/kerberos-5/krb5-1.2.1UM/@sys/dest/usr/krb5/include -I$(KINCDIR) -I/usr/local/openssl/include -I../libsnet

LIBCGI  = -Llibcgi -lcgi
LIBS	= $(LIBCGI) -L/usr/local/krb5/lib -lkrb5 -lk5crypto -lcom_err $(EX_LIBS) -L/usr/local/openssl/lib -lcrypto -L../libsnet -lsnet

LDFLAGS	= $(KLIBS)
CFLAGS	= -g -Wall $(INC)


all: ${TARGETS}

cosign: libs cgi.o $(OBJ)
		${CC} -o cosign cgi.o $(OBJ) $(LIBS) $(LDFLAGS)

logout: libs logout.o $(OBJ)
		${CC} -o logout logout.o $(OBJ) $(LIBS)

libs:
		cd ../libsnet; ${MAKE} ${MFLAGS} CC=${CC}
		cd libcgi; ${MAKE} ${MFLAGS} CC=${CC}

clean:
		cd ../libsnet; ${MAKE} clean
		cd libcgi; ${MAKE} clean
		/bin/rm -rf *.o ${TARGETS}

install: all
		/bin/cp $(TARGETS) $(CGIBIN)
		/bin/cp -r html/*.html $(TMPL)
		/bin/cp -r html/seal.gif $(HTML)
