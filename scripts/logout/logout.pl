#!/usr/local/bin/perl -wT

use strict;

# change 'central' to the url of your central weblogin server.
my $central = "https://weblogin.umich.edu/cgi-bin/logout";

# expire and nullify service cookie
print( "Set-Cookie: $ENV{ COSIGN_SERVICE }=null; path=/; expires=Wednesday, 27-Jan-77 00:00:00 GMT; secure\n" );

# perform any local cleanup here

# redirect to central weblogin server
print( "Location: $central\n\n" );

exit( 0 );
