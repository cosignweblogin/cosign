define( `LOGOUT_ONLOAD', `1' )
include(`header.html')

	<h5>WEBLOGIN:  YOU ARE NOT AUTHENTICATED</h5>
	<p>
	    Skip this screen in the future by visiting:
	</p>

	    <blockquote class="deep">
		https://$h/
	    </blockquote>

	<p>
	    <em>prior to</em> accessing a protected resource.
	</p>

	<p>
	    <form name="f" enctype="application/x-www-form-urlencoded"
		    method="post" action="/">
		<input type="hidden" name="ref" value="$r">
		<input type="hidden" name="key" value="$k">

		<input class="splash_button" name="verify" type="submit" value="  OK  ">
	    </form>
	</p>

include(`footer.html')
