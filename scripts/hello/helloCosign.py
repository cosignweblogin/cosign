#!/usr/local/bin/python

import os

print "Content-type: text/html\n\n"

print """
<html>
    <head>
	<title>hello, cosign ( python )</title>
    </head>

    <body>
	<h1>
"""

print "            Hello, ", os.environ['REMOTE_USER']

print """
!\n        </h1>
    </body>
</html>
"""

