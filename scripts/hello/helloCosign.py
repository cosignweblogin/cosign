#!/usr/local/bin/python

import os

print "Content-type: text/html\n\n"
print
print

print "Hello, ", os.environ['REMOTE_USER'], "!"

