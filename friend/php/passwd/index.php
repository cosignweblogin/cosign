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

    if ( !strlen( $_POST[ 'oldpw' ])) {
	$smarty->display( 'passwd.tpl' );
	exit( 0 );
    }

    // we'll need this to use in other strings.
    $REMOTE_USER = $_SERVER[ 'REMOTE_USER' ];

    // compare new passwords
    if ( ! strlen( $_POST[ 'passwd0' ])  || ! strlen( $_POST[ 'passwd1' ])) {
        $smarty->assign( 'error', 'Please be sure to enter your new password twice.' );
        $smarty->display( 'passwd.tpl' );
	exit( 0 );
    }

    if ( $_POST[ 'passwd0' ] != $_POST[ 'passwd1' ] ) {
        $smarty->assign( 'error', 'Passwords do not match, please re-enter.' );
        $smarty->display( 'passwd.tpl' );
	exit( 0 );
    }

    // connect to db for password verification and changing
    $db = mysql_connect( "FRIEND_DB", "FRIEND_LOGIN", "FRIEND_PASSWD" );

    if ( !$db ) {
        $smarty->assign( 'error', "mysql_connect failed" );
        $smarty->display( 'error.tpl' );
        exit( 0 );
    }

    mysql_select_db( "friend", $db );

    // verify old password is correct
    $row = mysql_query( "SELECT passwd FROM friends where account_name = '$REMOTE_USER'", $db );       

    if ( mysql_num_rows( $row ) < 1 ) {
	$smarty->assign( 'error', "You do not appear to have a Friend account: $REMOTE_USER" );
	$smarty->display( 'error.tpl' );

	mysql_close( $db );
	exit( 0 );
    }
    $db_passwd = mysql_result( $row, 0, "passwd" );

    if ( crypt( $_POST[ 'oldpw' ], $db_passwd ) != $db_passwd ) {
        $smarty->assign( 'error',  "Old password incorrect.  Is [caps lock] on?" );
        $smarty->display( 'passwd.tpl' );
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
        $smarty->display( 'passwd.tpl' );
	exit( 0 );
    }

    // store login and password in database
    $sql = "UPDATE friends SET passwd = '$passwd' WHERE account_name = '$REMOTE_USER'";

    $result = mysql_query( $sql );

    if ( !$result ) {
        $smarty->assign( 'error', mysql_error());
        $smarty->display( 'error.tpl' );
        exit( 0 );
    }

    mysql_close( $db );

    $smarty->assign( 'message',  "Password successfully changed." );
    $smarty->display( 'passwd_changed.tpl' );
?>
