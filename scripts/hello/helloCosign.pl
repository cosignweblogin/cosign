#!/usr/local/bin/perl -wT

use strict;

while( <DATA> ) {
    s/REMOTE_USER/$ENV{ REMOTE_USER }/;
    s/COSIGN_SERVICE/$ENV{ COSIGN_SERVICE }/;
    s/REMOTE_REALM/$ENV{ REMOTE_REALM }/;
    s/AUTH_TYPE/$ENV{ AUTH_TYPE }/;
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

	<table>
	    <tr> <td>Remote User</td> <td>REMOTE_USER</td> </tr>
	    <tr> <td>Cosign Service</td> <td>COSIGN_SERVICE</td> </tr>
	    <tr> <td>Remote Realm</td> <td>REMOTE_REALM</td> </tr>
	    <tr> <td>Auth Type</td> <td>AUTH_TYPE</td> </tr>
	</table>
    </body>
</html>
