#!/usr/local/bin/python

import os

print "Content-type: text/html\n\n"
print "Hello, ", os.environ['REMOTE_USER'], "!"

