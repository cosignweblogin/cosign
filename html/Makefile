ALL	= error.html login.html redirect.html service-menu.html splash.html
TMPL    = /usr/local/projects/cosign/templates
HTML    = /usr/local/projects/cosign/html

M4 = /usr/ccs/bin/m4

.SUFFIXES: .m4 .html

.m4.html:
	${M4} $*.m4 >$*.html

default: ${ALL}

install:
	/bin/cp -r seal.gif $(HTML)
	/bin/cp -r ${ALL} $(TMPL)

clean:
	/bin/rm -f ${ALL}
