<?php
    include_once( 'Smarty.class.php' );
    include_once( 'Mail.php' );
    include_once( 'Mail/mime.php' );
    include_once( 'Mail/RFC822.php' );

    $smarty = new Smarty;
    $smarty->compile_check = true;
    $smarty->debugging = false;

    session_start();

    if ( $_SERVER[ 'REQUEST_METHOD' ] != 'POST' ) {
	$_SESSION[ "cookies" ] = 'enabled';

	if ( $_SERVER[ 'REQUEST_METHOD' ] != 'GET' ) {
	    $smarty->assign( 'error', "Invalid Request." );
	    $smarty->display( 'error.tpl' );
	    exit( 0 );
	}

	if ( strlen( $_GET[ 'ref' ])) {
	    $_SESSION[ "ref" ] = $_GET[ 'ref' ];
	}

	$smarty->display( 'request.tpl' );
	exit( 0 );
    }

    if ( $_SESSION[ "cookies" ] != "enabled" ) {
	$smarty->assign( 'error', "Your browser does not appear to be accepting cookies." );
	$smarty->display( 'request.tpl' );
	exit( 0 );
    }

    // Load the mysql module
    if ( !extension_loaded( 'mysql' )) {
        if ( !dl( 'mysql.so' )) {
            $smarty->assign( 'error', "mysql not enabled" );
            $smarty->display( 'error.tpl' );
            exit( 0 );
        }
    }

    if ( !strlen( $_POST[ 'email' ])) {
        $smarty->assign( 'error', 'Please enter your email address.' );
	$smarty->display( 'request.tpl' );
	exit( 0 );
    }

    $rfc822  = new Mail_RFC822( $_POST[ 'email' ], '', TRUE );
    $smarty->assign( 'email', $_POST[ 'email' ]);

    $addresses = $rfc822->parseAddressList();

    if ( ! is_array( $addresses )) {
        $smarty->assign( 'error', 'Please enter your e-mail address.' );
	$smarty->display( 'request.tpl' );
	exit( 0 );
    }

    $addr = array_shift( $addresses );

    if ( empty( $addr->host ) || empty( $addr->mailbox )) {
        $smarty->assign( 'error', 'Please enter a valid email address.' );
	$smarty->display( 'request.tpl' );
	exit( 0 );
    }

    // XXX make sure host exists ( and has MX? )
    $rcpt = $addr->mailbox . "@" . $addr->host;
    $smarty->assign( 'rcpt', $rcpt );

    // XXX block domains that cannot contain friends here ( e.g. umich.edu )
    if ( preg_match( "/@.*\.?umich.edu$/i", $rcpt )) {
        $smarty->assign( 'error', "Friend accounts may not be created for our default domain: $rcpt" );
        $smarty->display( 'error_default_domain.tpl' );

       exit( 0 );
    }

    // make sure rcpt doesn't already have an account
    $db = mysql_connect( "FRIEND_DB", "FRIEND_LOGIN", "FRIEND_PASSWD" );

    if ( !$db ) {
        $smarty->assign( 'error', "mysql_connect failed" );
        $smarty->display( 'error.tpl' );
        exit( 0 );
    }

    mysql_select_db( "friend", $db );

    $row = mysql_query( "SELECT account_name FROM friends where account_name = '$rcpt'", $db );

    if ( mysql_num_rows( $row ) > 0 ) {
	if ( mysql_result( $row, 0, "account_name" )) {
	    $smarty->assign( 'error', "Your account already exists: $rcpt" );
	    $smarty->display( 'error.tpl' );

	    mysql_close( $db );
	    exit( 0 );
	}
    }

    // no account, is there a request pending?
    $row = mysql_query( "SELECT token FROM acquaintances where account_name = '$rcpt' AND timestamp >= NOW() - 86400", $db );

    if ( mysql_num_rows( $row ) > 0 ) {
	if (( $token = mysql_result( $row, 0, "token" )) != NULL ) {
	    // request already pending.
	    // re-send message and display "message sent" screen.
	}
    } else {

	// no pending token, generate token for request
	$key = '';

	// build and shuffle range using ASCII table
	for ( $i=0; $i<=255; $i++ ) {
	    $range[] = chr( $i );
	}

	// shuffle our range 3 times
	for ( $i=0; $i<=3; $i++ ) {
	    shuffle( $range );
	}

	// loop for random number generation
	for ( $i = 0; $i < mt_rand( 32, 64 ); $i++ ) {
	    $key .= $range[ mt_rand( 0, count( $range ))];
	}

	$token = base64_encode( $key );

	if ( empty( $token )) {
	    // error, key was empty for some reason
	}

	if ( isset( $_SESSION[ "ref" ])) {
	    $ref = $_SESSION[ "ref" ];
	}

	// insert request in acquaintances table.
	$sql = "INSERT INTO acquaintances ( account_name, token, ref, timestamp ) VALUES ( '$rcpt', '$token', '$ref', NOW())";

	if ( ! mysql_query( $sql )) {
	    $smarty->assign( 'error', mysql_error());
	    $smarty->display( 'error.tpl' );
	    mysql_close( $db );
	    exit( 0 );
	}
    }
    mysql_close( $db );

    // send message
    $smarty->assign( 'bundle', $rcpt . "==" . $token );
    $text = $smarty->fetch( 'message.tpl' );
    $html = $smarty->fetch( 'message_html.tpl' );

    $crlf = "\r\n";

    $hdrs = array(
	    'From' => 'friend-noreply@umich.edu',
	    'Subject' => 'U of M: Friend Account Request',
	    'Precedence' => 'Junk'
    );

    $mime = new Mail_mime( $crlf );

    $mime->setTXTBody( $text );
    $mime->setHTMLBody( $html );

    $body = $mime->get();
    $hdrs = $mime->headers( $hdrs );

    $mail =& Mail::factory( 'mail' );
    $mail->send( $rcpt, $hdrs, $body );

    $smarty->display( 'message_sent.tpl' );
?>
