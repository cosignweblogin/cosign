CGIBIN	= /usr/local/projects/cosign/cgi-ssl

CC	= gcc
DEFS	= -DTLS
TARGETS	= cosign logout
OBJ	= mkcookie.o fbase64.o network.o

KDIR	= /usr/local/krb5
KLIBDIR	= $(KDIR)/lib
KINCDIR	= $(KDIR)/include
#KLIBS	= $(KLIBDIR)/libkrb.a $(KLIBDIR)/libdes.a
EX_LIBS	= -lsocket -lnsl -lresolv

INC	= -I../libcgi -I/afs/umich.edu/group/itd/software/packages/k/kerberos-5/krb5-1.2.1UM/@sys/dest/usr/krb5/include -I$(KINCDIR) -I/usr/local/openssl/include -I../libsnet

LIBCGI  = -L../libcgi -lcgi
LIBS	= $(LIBCGI) -L/usr/local/krb5/lib -lkrb5 -lk5crypto -lcom_err $(EX_LIBS) -L/usr/local/openssl/lib -lssl -lcrypto -L../libsnet -lsnet

LDFLAGS	= $(KLIBS)
CFLAGS	= -g -Wall $(DEFS) $(INC)


all: ${TARGETS}

cosign: cgi.o $(OBJ)
		${CC} -o cosign cgi.o $(OBJ) $(LIBS) $(LDFLAGS)

logout: logout.o $(OBJ)
		${CC} -o logout logout.o $(OBJ) $(LIBS)


clean:
		/bin/rm -rf *.o ${TARGETS}

install: all
		/bin/cp $(TARGETS) $(CGIBIN)
