define( `LOGOUT_ONLOAD', `1' )
include(`header.html')

	<h5>LOGOUT</h5>
	<p>
	    Are you sure you want to quit all UM web applications
	    and log out now?
	</p>

	<p align="center">
	    <form name="f" method="post" action="/cgi-bin/logout">
		<input type="submit" value="Cancel" />

		&nbsp;
		&nbsp;
		&nbsp;

		<input type="hidden" name="url" value="$l" />
		<input type="submit" name="verify" value="Logout" />
	    </form>
	</p>

	<p class="small">
	    After logout your browser will redirect to: $l
	</p>

include(`footer.html')
