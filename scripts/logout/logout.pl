#!/usr/local/bin/perl -wT

use strict;

# change 'central' to the url of your central weblogin server.
my $central = "https://weblogin.umich.edu/cgi-bin/logout";

# change 'service' to your service name.
my $service = "mail";

# expire and nullify service cookie
print( "Set-Cookie: cosign-$service=null; path=/; expires=Wednesday, 16-Apr-73 02:10:00 GMT; secure\n" );

# perform any local cleanup here

# redirect to central weblogin server
print( "Location: $central\n\n" );

exit( 0 );
