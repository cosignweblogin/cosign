define( `LOGOUT_ONLOAD', `1' )
include(`header.html')

	<h5>LOGOUT</h5>
	<p>
	    You are about to logout of <a href="/">all weblogin
	    applications</a>.  Are you sure you want to do this?
	</p>

	<p class="centerBodyText">
	    <form name="f" method="post" action="/cgi-bin/logout">
		<input type="button" value="Back" onClick="history.go(-1)">

		&nbsp;
		&nbsp;
		&nbsp;

		<input type="hidden" name="url" value="$u" />
		<input type="submit" name="verify" value="Logout" />
	    </form>
	</p>

	<p class="smallBodyText">
	    After logout your browser will redirect to: $u
	</p>

include(`footer.html')
