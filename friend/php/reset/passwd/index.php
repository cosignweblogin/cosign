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

    session_start();

    if ( $_SERVER[ 'REQUEST_METHOD' ] != 'POST' ) {
	header( 'Location: /friend/' );
	exit( 0 );
    }

    if ( !strlen( $_POST[ 'request' ])) {
        $smarty->assign( 'error', 'Unable to process request ( Please double-check the URL and try again ).' );
        $smarty->display( 'error.tpl' );
        exit( 0 );
    }

    // verify rcpt is valid e-mail addr
    $rcpt = ( $_POST[ 'login' ]);

    $str = base64_decode( $_POST[ 'request' ]);
    $token = base64_encode( $str );

    if ( $rcpt != $_SESSION[ "rcpt" ] ||
	    $token != $_SESSION[ "token" ] ) {
	// user did not get here properly
        $smarty->assign( 'error', 'Unable to process request ( Please double-check the URL you were mailed, make sure your browser is accepting cookies from this site,  and try again. ).' );
        $smarty->display( 'error.tpl' );
        exit( 0 );
    }

    $smarty->assign( 'login', $rcpt );
    $smarty->assign( 'request', $token );

    // compare passwords
    if ( ! strlen( $_POST[ 'passwd0' ])  || ! strlen( $_POST[ 'passwd1' ])) {
        $smarty->assign( 'error', 'Please be sure to enter your new password twice.' );
        $smarty->display( 'reset.tpl' );
	exit( 0 );
    }

    if ( $_POST[ 'passwd0' ] != $_POST[ 'passwd1' ] ) {
        $smarty->assign( 'error', 'Passwords do not match, please re-enter.' );
        $smarty->display( 'reset.tpl' );
	exit( 0 );
    }

    // passwd gets points for lower/upper case, digits, and punctuation
    $score = 0;
    $passwd = '';
    if ( ereg( "[[:lower:]]", $_POST[ 'passwd0' ])) {
	$score++;
    }

    if ( ereg( "[[:upper:]]", $_POST[ 'passwd0' ])) {
	$score++;
    }

    if ( ereg( "[[:digit:]]", $_POST[ 'passwd0' ])) {
	$score++;
    }

    if ( ereg( "[[:punct:]]", $_POST[ 'passwd0' ])) {
	$score++;
    }

    // XXX set minimum score in conf file
    if ( strlen( $_POST[ 'passwd0' ] ) >= 5 &&
	    $score >= 2 ) {
	// crypt with md5
	$passwd = crypt( $_POST[ 'passwd0' ]);
    } else {
	// passwd is crap.
        $smarty->assign( 'error', 'Requested password is too simple and could be easily guessed, please try a stronger password ( e.g. try a mixture of upper/lower case with a number or punctuation mark ).' );
        $smarty->display( 'reset.tpl' );
	exit( 0 );
    }

    // store login and password in database
    $db = mysql_connect( "FRIEND_DB", "FRIEND_LOGIN", "FRIEND_PASSWD" );

    if ( !$db ) {
        $smarty->assign( 'error', "mysql_connect failed" );
        $smarty->display( 'error.tpl' );
        exit( 0 );
    }

    mysql_select_db( "friend", $db );

    $sql = "UPDATE friends SET passwd = '$passwd' WHERE account_name = '$rcpt'";
    $result = mysql_query( $sql );

    if ( !$result ) {
        $smarty->assign( 'error', mysql_error());
        $smarty->display( 'error.tpl' );
        exit( 0 );
    }

    // expire the reset key right away.
    $sql = "DELETE from resets WHERE account_name = '$rcpt'";
    $result = mysql_query( $sql );

    if ( !$result ) {
        $smarty->assign( 'error', mysql_error());
        $smarty->display( 'error.tpl' );
        exit( 0 );
    }

    mysql_close( $db );
    session_destroy();

    // display success screen
    $smarty->assign( 'request', $_POST[ 'request' ]);
    $smarty->display( 'passwd_has_been_reset.tpl' );
?>
