<?php
    include_once( 'Smarty.class.php' );

    $smarty = new Smarty;
    $smarty->compile_check = true;
    $smarty->debugging = false;

    // Load the mysql module
    if ( !extension_loaded( 'mysql' )) {
        if ( !dl( 'mysql.so' )) {
            $smarty->assign( 'error', "mysql not enabled" );
            $smarty->display( 'error.tpl' );
            exit( 0 );
        }
    }

    if ( $_SERVER[ 'REQUEST_METHOD' ] != 'GET' || !$_GET[ 'login' ]) {
        header( 'Location: /friend/' );
        exit( 0 );
    }

    $login = $_GET[ 'login' ]

    // connect to db for password verification and changing
    $db = mysql_connect( "FRIEND_DB", "FRIEND_LOGIN", "FRIEND_PASSWD" );

    if ( !$db ) {
        $smarty->assign( 'error', "mysql_connect failed" );
        $smarty->display( 'error.tpl' );
        exit( 0 );
    }

    mysql_select_db( "friend", $db );

    $row = mysql_query( "SELECT passwd FROM friends where account_name = '$REMOTE_USER'", $db );       

    if ( mysql_num_rows( $row ) < 1 ) {
	$smarty->assign( 'error', "FALSE: no such account" );
    } else {
	$smarty->assign( 'error', "TRUE: account exists" );
    }

    if ( !$_GET[ 'password' ]) {
	// no password to check, we're done.
	$smarty->display( 'lookup.tpl' );
    }

    $db_passwd = mysql_result( $row, 0, "passwd" );

    if ( crypt( $_GET[ 'password' ], $db_passwd ) != $db_passwd ) {
        $smarty->assign( 'error',  "FALSE: password incorrect" );
    } else {
        $smarty->assign( 'error',  "TRUE: password correct" );
    }

    mysql_close( $db );
    $smarty->display( 'lookup.tpl' );
    exit( 0 );  
?>
