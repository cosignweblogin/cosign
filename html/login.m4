define( `LOGIN_ONLOAD', `1' )
include(`header.html')

<h5>AUTHENTICATION REQUIRED</h5>
<form name="f" action="/"
	enctype="application/x-www-form-urlencoded"
	method="post" autocomplete="off">
<input type="hidden" name="ref" value="$r">
<input type="hidden" name="service" value="$c">

<p>
    By using this service you agree to adhere to <a
    href="http://www.umich.edu/~policies/">
    UM computing policies and guidelines</a>. Please
    type your login and password and click
    the &#8220;Login&#8221; button to continue.
</p> 

<table align="center" summary="separates login and password fields">
    <tr>
	<td bgcolor="#FFFFFF">
	    <p>
		<b><label for="login">login</label>:</b>
	    </p>
	</td>

	<td bgcolor="#FFFFFF">
	    <input id="login" name="login" size="24" value="$l">
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
	    <td height=1 bgcolor="#FFCC00" width="737" colspan="2"> <img src="/images/spacer.gif" width="737" height="1" alt="" border="0"> </td>
	</tr>
	<tr>
	    <td height=10 width="737" colspan="2" bgcolor="ffffff">
		<img src="/images/spacer.gif" width="1" height="10"
		alt="" border="0">
	    </td>
	</tr>

	<tr>
	    <td valign="top" class="lower" bgcolor="ffffff">
		<p>Need An Account?</p>
		<ul>
		<li><a href="http://www.itd.umich.edu/help/faq/uniqnames/get.html">Faculty, Staff, and Students </a><br />
		All UM students, faculty, and staff should have a uniqname.<br />

		<li><a href="https://accounts.www.umich.edu/create/alumnirec/">Alumni</a><br /> UM Alumni are eligible to create an account.

		<!--
		<li><a href="https://weblogin-test.www.umich.edu/friend/">Friends</a><br />
		Create a 'Friend' account if you are not otherwise affiliated with the University.<br />
		-->
		</ul>
	    </td>

	    <td valign="top" class="lower" bgcolor="ffffff">
		<p>Forget Your Password?</p>
		<ul>
		<li><a href="https://accounts.www.umich.edu/hint-bin/retrieve">Retrieve your hint</a><br />
		If you've left yourself a hint you can use it to remind yourself of your password.<br />

		<!--
		<li><a href="https://weblogin-test.www.umich.edu/friend/passwd/">Reset your Friend password</a><br />
		If you have a Friend account (not a UM uniqname), you can reset the password online. <br />
		-->
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
