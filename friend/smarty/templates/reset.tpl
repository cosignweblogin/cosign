{include file="header.tpl"}

<h5>RESET PASSWORD: {$login|upper|escape}</h5>

<p>
    Welcome back!  The next step in the password reset process is
    to reset your password.  Please protect your digital identity by
    choosing a secure password -- something you can easily remember but
    others will find difficult to guess.
</p>

<form name="f" action="/friend/reset/passwd/" method="post"
	enctype="application/x-www-form-URLencoded">

    <p>&nbsp;</p>

    <table>
	<tr>
	    <td align="right">
		<b><label for="passwd">Password</label>:</b>
	    </td>
	    <td>
		<input type="password" id="passwd0" name="passwd0"
			size="20" maxlength="60" autocomplete="off">
	    </td>
	</tr>

	<tr>
	    <td align="right">
		<b><label for="passwd">Confirm Password</label>:</b>
	    </td>
	    <td>
		<input type="password" id="passwd1" name="passwd1"
			size="20" maxlength="60" autocomplete="off">
	    </td>
	</tr>

	<tr>
	    <td colspan="2" align="right">
		<input type="hidden" name="login" value="{$login|escape}">
		<input type="hidden" name="request" value="{$request|escape}">
		<input type="submit" value="Reset Password">
	    </td>
	</tr>
    </table>
</form>

<p>
    A good password should be at least six characters long and contain
    MIxeD cAsE letters, numbers, and punctuation.
</p>

<p class="error">
    {$error}
</p>

{include file="footer.tpl"}


