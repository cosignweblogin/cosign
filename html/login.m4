define( `LOGIN_ONLOAD', `1' )
include(`header.html')

<h5>AUTHENTICATION REQUIRED</h5>
<form name="f" action="/"
	enctype="application/x-www-form-urlencoded"
	method="post" autocomplete="off">
<input type="hidden" name="ref" value="$r">

<p>
    By using this service you agree to adhere to <a
    href="http://www.umich.edu/~policies/">
    UM computing policies and guidelines</a>. Please
    type your uniqname and password and click
    the &#8220;Login&#8221; button to continue.
</p> 

<table align="center" summary="separates uniqname and password fields">
    <tr>
	<td bgcolor="#FFFFFF">
	    <p>
		<b><label for="uniqname">uniqname</label>:</b>
	    </p>
	</td>

	<td bgcolor="#FFFFFF">
	    <input id="uniqname" name="uniqname" size="24" maxlength="8" value="$u">
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
	    <input type="submit" value="Login">
	    <p class="error" align="center">$e</p>
	</td>
    </tr>
</table>

</form>

<br />
</td>

<td width="70"><img src="/images/spacer.gif" width="70" alt="" border="0"></td></tr>

<tr>
 <td colspan="3" bgcolor="#FFFFFF" width="737">
    <table width="737" border="0" cellspacing="0" cellpadding="0">
	<tr>
	    <td height=1 bgcolor="#FFCC00" width="737"> <img src="/images/spacer.gif" width="737" height="1" alt="" border="0"> </td>
	</tr>
	<tr>
	    <td height=10 width="737">
		<img src="/images/spacer.gif" width="1" height="10"
		alt="" border="0">
	    </td>
	</tr>

	<tr>
	    <td>
		<ul>
		<li><a href="http://www.itd.umich.edu/help/faq/uniqnames/get.html">Faculty, Staff, and Students: Get an Account</a><br />
		A valid UM login is required to use this
		service;  find out how to get yours.<br />

		<li><a href="https://login.www.umich.edu/cgi-bin/new_account">Alumni: Create an Account</a><br />
		UM Alumni are eligible to create an account to
		stay in touch with the University.
		</ul>
	    </td>
	</tr>
    </table>
</td>
</tr>
</table>

</div>
</body>
</html>
