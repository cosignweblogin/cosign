#!/usr/local/bin/perl -wT

use strict;

while( <DATA> ) {
    s/REMOTE_USER/$ENV{ REMOTE_USER }/;
    print();
}

exit();

__END__
Content-type: text/html

<html>
    <head>
        <title>hello, cosign ( perl )</title>
    </head>

    <body>
        <h1>
            Hello, REMOTE_USER!
        </h1>
    </body>
</html>
