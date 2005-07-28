<?php
    /* change 'central' to the url of your weblogin server */
    $central = "https://weblogin.umich.edu/cgi-bin/logout";

    setcookie( $_SERVER[ 'COSIGN_SERVICE' ], "null", time()-1, '/', "", 1 );

    /* make any local additions here (e.g. expiring local sessions, etc.),
       but it's important that there be no output on this page. */

    header( "Location: $central" );
    exit;
?>
