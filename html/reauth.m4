define( `LOGIN_ONLOAD', `1' )
include(`header.html')

<form name="f" action="/"
	enctype="application/x-www-form-urlencoded"
	method="post" autocomplete="off">
<input type="hidden" name="ref" value="$r">
<input type="hidden" name="service" value="$c">
<input type="hidden" name="reauth" value="true">
<input type="hidden" name="login" value="$l">

<p>
The service you were attempting to access requires that you verify your identity by authenticating again.
</p> 

<table align="center" summary="separates login and password fields">
    <tr>
	<td bgcolor="#FFFFFF">
	    <p>
		<b><label for="login">login</label>:</b>
	    </p>
	</td>

	<td bgcolor="#FFFFFF">
	$l
	</td>
    </tr>

    <tr>
	<td bgcolor="#FFFFFF">
	    <p>
		<b><label for="password">password</label>:</b>
	    </p>
	</td>

	<td bgcolor="#FFFFFF">
	    <input value="" size="24" id="password"
		    name="password" type="password"
		    autocomplete="off">
	</td>
    </tr>

    <tr>
	<td colspan="2" align="right" bgcolor="#FFFFFF">
	    <input type="submit" value="Re-Authenticate">
	    </form>
	    <form name="switch" action="/cgi-bin/logout"
	    enctype="application/x-www-form-urlencoded"
	    method="post" autocomplete="off">
	    <input type="hidden" name="url" value="$r">
	    <input type="hidden" name="service" value="$c">
	    <input type="hidden" name="reauth" value="true">
	    <input type="hidden" name="login" value="$l">
	    <input type="submit" name="verify" value="Switch Users">
	    </form>
	    <p class="error" align="center">Please type your password and click the Re-Authenticate button to continue. If you are not this user, click the Switch Users button to login as yourself.</p>
	</td>
    </tr>
</table>

</form>

include(`footer.html')
