<?php

    include( 'Smarty.class.php' );

    // Load the mysql module
    if ( !extension_loaded( 'mysql' )) {
        if ( !dl( 'mysql.so' )) {
            $smarty->assign( 'error', "mysql not enabled" );
            $smarty->display( 'error.tpl' );
            exit( 0 );
        }
    }

    $smarty = new Smarty;
    $smarty->compile_check = true;
    $smarty->debugging = false;

    if ( $_SERVER[ 'REQUEST_METHOD' ] != 'GET' ) {
	header( 'Location: /friend/' );
	exit( 0 );
    }

    if ( !strlen( $_GET[ 'r' ])) {
        $smarty->assign( 'error', 'Unable to process request ( please double-check the URL and try again ).' );
        $smarty->display( 'error.tpl' );
        exit( 0 );
    }

    // XXX check for sql injection
    list( $rcpt, $token ) =  explode( "==", $_GET[ 'r' ], 2 );

    // verify that rcpt is a valid e-mail address

    // is the token valid base64?
    $str = base64_decode( $token );
    $token = base64_encode( $str );

    // verify token & make sure login doesn't already have an account
    $db = mysql_connect( "FRIEND_DB", "FRIEND_LOGIN", "FRIEND_PASSWD" );

    if ( !$db ) {
        $smarty->assign( 'error', "mysql_connect failed" );
        $smarty->display( 'error.tpl' );
        exit( 0 );
    }

    mysql_select_db( "friend", $db );

    // XXX 3600 should not be hard-coded here.
    $row = mysql_query( "SELECT account_name, token FROM resets where account_name = '$rcpt' AND token = '$token' AND timestamp >= NOW() - 3600", $db );

    if ( mysql_num_rows( $row ) < 1 ) {
	$smarty->assign( 'error', "No pending request for $rcpt with this token." );
	$smarty->display( 'error_bogus_reset.tpl' );

	mysql_close( $db );
	exit( 0 );
    }

    $row = mysql_query( "SELECT account_name FROM friends where account_name = '$rcpt'", $db );

    if ( mysql_num_rows( $row ) < 1 ) {
	$smarty->assign( 'error', "This account does not exist: $rcpt" );
	$smarty->display( 'error.tpl' );

	mysql_close( $db );
	exit( 0 );
    }

    mysql_close( $db );

    session_start();
    $_SESSION[ "rcpt" ] = $rcpt;
    $_SESSION[ "token" ] = $token;

    $smarty->assign( 'request', $token );
    $smarty->assign( 'login', $rcpt );
    $smarty->display( 'reset.tpl' );
?>
