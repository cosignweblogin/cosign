CGIBIN = /afs/umich.edu/user/c/l/clunis/Public/xcgi/cgi-ssl
HTML = /afs/umich.edu/user/c/l/clunis/Public/xcgi/html-ssl/

CC	 = gcc
TARGETS	 = cosign
OBJ 	 = cgi.o mkcookie.o fbase64.o

KRBDIR	  = /afs/umich.edu/group/itd/build/webmaster/projects/weblogin/cookieserver/sun4x_56_krb
KRBLIBDIR = $(KRBDIR)/lib
KRBINCDIR = $(KRBDIR)/include
KRBLIBS	  = $(KRBLIBDIR)/libkrb.a \
            $(KRBLIBDIR)/libdes.a

INCLUDES = -Ilibcgi -I/afs/umich.edu/group/itd/software/packages/k/kerberos-5/krb5-1.2.1UM/@sys/dest/usr/krb5/include -I$(KRBINCDIR) -I/usr/local/openssl/include -I../libsnet

DEBUGFLAGS = -g

EX_LIBS	 = -lsocket -lresolv -lxnet

LIBS	 = -Llibcgi -lcgi -L/afs/umich.edu/group/itd/software/packages/k/kerberos-5/krb5-1.2.1UM/@sys/dest/usr/krb5/lib -lkrb5 -lk5crypto -lcom_err $(EX_LIBS) -L/usr/local/openssl/lib -lcrypto -L../libsnet -lsnet

LDFLAGS = $(KRBLIBS)

CFLAGS  = $(DEBUGFLAGS) $(INCLUDES)


all: ${TARGETS}

cosign: libs $(OBJ)
		${CC} -o cosign $(OBJ) $(LIBS) $(LDFLAGS)

libs:
		cd ../libsnet; ${MAKE} ${MFLAGS} CC=${CC}
		cd libcgi; ${MAKE} ${MFLAGS} CC=${CC}

clean:
		cd ../libsnet; ${MAKE} clean
		cd libcgi; ${MAKE} clean
		/bin/rm -rf *.o ${TARGETS}

install:
		/bin/cp cosign $(CGIBIN)
		/bin/cp -r html/* $(HTML)
